from __future__ import annotations

import asyncio
import logging
import os
import signal
from contextlib import suppress
from math import isfinite
from typing import Protocol, cast

from connected_vehicle.remote_command.outbox_runtime import remote_command_outbox_runtime
from enterprise_platform.config.settings import Settings, get_settings
from enterprise_platform.reliability.policies import RetryPolicy

logger = logging.getLogger(__name__)


class BatchDispatcher(Protocol):
    async def dispatch_batch(self) -> object: ...


def resolve_dispatcher(runtime: object) -> BatchDispatcher:
    # Support context managers that yield the dispatcher directly or a runtime
    # holder exposing .dispatcher. Neither path creates a second DB connection.
    candidate = getattr(runtime, "dispatcher", runtime)
    if not callable(getattr(candidate, "dispatch_batch", None)):
        raise TypeError("Outbox runtime must expose dispatch_batch().")
    return cast(BatchDispatcher, candidate)


def _positive_interval(name: str, default: float) -> float:
    value = float(os.environ.get(name, str(default)))
    if not isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number.")
    return value


def _install_shutdown_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Signal registration is unavailable on some Windows event loops.
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)


async def _sleep_or_stop(stop: asyncio.Event, seconds: float) -> None:
    with suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


async def run(settings: Settings | None = None) -> None:
    settings = settings if settings is not None else get_settings()
    interval = _positive_interval("OUTBOX_POLL_SECONDS", 1.0)
    retry_policy = RetryPolicy(
        max_attempts=5,
        base_delay_seconds=1.0,
        max_delay_seconds=30.0,
        jitter_ratio=0.2,
    )
    stop = asyncio.Event()
    _install_shutdown_handlers(stop)

    # The context manager must load DatabaseRuntime.OUTBOX and dispose its pool.
    async with remote_command_outbox_runtime(settings, retry_policy) as resource:
        dispatcher = resolve_dispatcher(resource)
        logger.info("Outbox dispatcher started")
        while not stop.is_set():
            # Unexpected failures are fatal: the process supervisor can restart
            # the worker, rather than silently dropping events.
            await dispatcher.dispatch_batch()
            await _sleep_or_stop(stop, interval)
    logger.info("Outbox dispatcher stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    with suppress(KeyboardInterrupt):
        asyncio.run(run())


if __name__ == "__main__":
    main()
