"""Poll frozen rollouts with the tenant-bound application runtime identity, never DDL."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from contextlib import suppress
from uuid import UUID, uuid4

from connected_vehicle.ota.artifacts import ArtifactVerifier
from connected_vehicle.ota.campaign_service import CampaignService
from connected_vehicle.ota.service import OTAService
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from enterprise_platform.database.session import create_session_factory


async def run(identifier: str | None, once: bool, interval: float, crash: bool = False) -> None:
    settings = Settings()
    if not settings.database_tenant_id:
        raise ValueError("A fixed database tenant binding is required")
    if crash and (
        settings.cloud_runtime.value != "localstack"
        or settings.app_env.value not in {"local", "test"}
    ):
        raise ValueError("Fault injection is local-only")
    engine = create_database_engine(await load_runtime_database_settings(settings, "application"))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    previous = {}
    handled = [signal.SIGINT, signal.SIGTERM]
    if (windows_break := getattr(signal, "SIGBREAK", None)) is not None:
        handled.append(windows_break)
    for sig in handled:
        previous[sig] = signal.getsignal(sig)
        signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))
    try:
        await verify_runtime_database_security(
            engine, "application", tenant_id=settings.database_tenant_id
        )
        campaigns = CampaignService(
            OTAService(create_session_factory(engine)), ArtifactVerifier(settings)
        )
        cursor = ""
        failures = 0
        while not stop.is_set():
            ids = (
                [identifier]
                if identifier
                else await campaigns.running(settings.database_tenant_id, cursor)
            )
            if not identifier:
                cursor = ids[-1] if ids else ""
            for current in ids:
                if stop.is_set():
                    break
                if crash:
                    await campaigns.tick(
                        settings.database_tenant_id, "campaign-dispatcher", current, str(uuid4())
                    )
                    os._exit(91)
                # A deadline cancels IO; transaction rollback or durable operation IDs handle retry.
                try:
                    async with asyncio.timeout(120):
                        result = await campaigns.dispatch(settings.database_tenant_id, current)
                except Exception as exc:
                    failures += 1
                    print(
                        json.dumps(
                            dict(
                                campaign_id=current,
                                event="dispatch_error",
                                error_type=type(exc).__name__,
                                attempt=failures,
                            )
                        ),
                        flush=True,
                    )
                    if once or failures >= 3:
                        raise
                    with suppress(TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=min(30, 2**failures))
                    continue
                print(
                    json.dumps(
                        dict(
                            campaign_id=str(result.id),
                            status=result.status,
                            current_wave=result.current_wave,
                            jobs=result.job_count,
                            succeeded=result.succeeded,
                            failed=result.failed,
                            pause_reason=result.pause_reason,
                        )
                    ),
                    flush=True,
                )
            if once:
                break
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=UUID)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--crash-after-jobs", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval <= 300:
        parser.error("interval must be between 1 and 300 seconds")
    try:
        asyncio.run(
            run(
                str(args.campaign) if args.campaign else None,
                args.once,
                args.interval,
                args.crash_after_jobs,
            )
        )
    except Exception as exc:
        # Never print SQL parameters, capabilities or connection credentials.
        print("Campaign dispatcher failed: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
