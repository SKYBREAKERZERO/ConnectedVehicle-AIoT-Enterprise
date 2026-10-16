"""Real API process, restricted identity, failed canary then recovery; no service mocks."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2 as httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import text

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.reliability.slo import CanaryWindow, evaluate_window
from scripts.day16_evidence import provenance
from scripts.day17_release import evaluate, readiness_digest, verify_readiness, write_json
from scripts.day17_rules import ROOT, policy
from tests.e2e.test_independent_runtimes import free_port
from tests.integration.day12.test_credential_cloud_contracts import prepare


def counters(body: str) -> dict[str, int]:
    result = {"requests": 0, "errors": 0, "duration_count": 0}
    for family in text_string_to_metric_families(body):
        for sample in family.samples:
            if sample.labels.get("route") != "/health/ready":
                continue
            if sample.name == "vehicle_http_requests_total":
                result["requests"] += int(sample.value)
                if sample.labels.get("status") != "200":
                    result["errors"] += int(sample.value)
            elif sample.name == "vehicle_http_duration_seconds_count":
                result["duration_count"] += int(sample.value)
    return result


@pytest.mark.integration
async def test_failed_canary_aborts_then_recovery_can_proceed(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    _, _, settings, _ = await prepare(local_environment, "day17-canary")
    runtime = await load_runtime_database_settings(settings, "application")
    assert re.fullmatch(r"app_user__[0-9a-f]{12}", runtime.database_username)
    admin = create_database_engine(local_environment)
    port, token = free_port(), uuid4().hex * 2
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OIDC_", "API_SERVICE_"))
    }
    environment.update(
        PYTHONPATH=str(ROOT),
        APP_ENV="local",
        CLOUD_RUNTIME="localstack",
        APP_HOST="127.0.0.1",
        APP_PORT=str(port),
        AWS_ENDPOINT_URL=str(settings.aws_endpoint_url),
        AWS_REGION=settings.aws_region,
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_CONFIG_FILE=str(tmp_path / "no-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(tmp_path / "no-creds"),
        DATABASE_TENANT_ID="day17-canary",
        APPLICATION_DATABASE_SECRET_ID=str(settings.application_database_secret_id),
        METRICS_TOKEN=token,
        TRACING_ENABLED="false",
        DATABASE_POOL_SIZE="2",
        DATABASE_MAX_OVERFLOW="0",
        DATABASE_CONNECT_TIMEOUT_SECONDS="0.5",
        DATABASE_HEALTH_TIMEOUT_SECONDS="1",
    )
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        flags = 0
    output = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    process: subprocess.Popen[bytes] | None = None
    limit: int | None = None
    windows: list[dict[str, Any]] = []
    log = (tmp_path / "api.log").open("wb")

    async def set_limit(value: int) -> None:
        assert -1 <= value <= 1000
        async with admin.begin() as connection:
            await connection.execute(
                text(f'ALTER ROLE "{runtime.database_username}" CONNECTION LIMIT {value}')
            )

    try:
        async with admin.connect() as connection:
            limit = await connection.scalar(
                text("SELECT rolconnlimit FROM pg_roles WHERE rolname=:role"),
                {"role": runtime.database_username},
            )
        assert isinstance(limit, int)
        process = subprocess.Popen(
            [sys.executable, "-m", "apps.api"],
            cwd=tmp_path,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=3, trust_env=False
        ) as client:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "Restricted API failed startup"
                try:
                    if (await client.get("/health/ready")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise AssertionError("API startup deadline exceeded")
                await asyncio.sleep(0.1)

            async def metrics() -> dict[str, int]:
                response = await client.get(
                    "/metrics", headers={"Authorization": "Bearer " + token}
                )
                assert response.status_code == 200
                return counters(response.text)

            async def window(phase: str) -> dict[str, Any]:
                before = await metrics()
                started = datetime.now(UTC).isoformat()
                samples = []
                try:
                    if phase == "fault":
                        await set_limit(0)
                        async with admin.begin() as connection:
                            await connection.execute(
                                text(
                                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                    "WHERE usename=:role AND pid<>pg_backend_pid()"
                                ),
                                {"role": runtime.database_username},
                            )
                    for index in range(policy().minimum_requests):
                        if phase == "fault" and index == 5:
                            await set_limit(limit)
                        tick = time.monotonic()
                        response = await client.get("/health/ready")
                        samples.append(
                            {
                                "status": response.status_code,
                                "elapsed_seconds": time.monotonic() - tick,
                            }
                        )
                        assert response.status_code == (
                            503 if phase == "fault" and index < 5 else 200
                        )
                finally:
                    await set_limit(limit)
                ended = datetime.now(UTC).isoformat()
                after = await metrics()
                row = dict(
                    window_id=uuid4().hex,
                    phase=phase,
                    started_at=started,
                    ended_at=ended,
                    route="/health/ready",
                    samples=samples,
                    metrics_delta={key: after[key] - before[key] for key in before},
                )
                parsed = CanaryWindow.model_validate_json(json.dumps(row))
                decision = evaluate_window(parsed, policy(), now=datetime.now(UTC))
                assert decision["decision"] == ("abort" if phase == "fault" else "proceed")
                print(
                    f"Day17 {phase}: {decision['decision']}, "
                    f"availability={decision['availability']}, p95={decision['p95_seconds']}",
                    flush=True,
                )
                return row

            async with asyncio.timeout(120):
                windows.append(await window("fault"))
                windows.append(await window("recovered"))
        async with admin.connect() as connection:
            restored = await connection.scalar(
                text("SELECT rolconnlimit FROM pg_roles WHERE rolname=:role"),
                {"role": runtime.database_username},
            )
        reader = create_database_engine(runtime)
        try:
            async with reader.connect() as connection:
                attributes = (
                    (
                        await connection.execute(
                            text(
                                "SELECT r.rolsuper,r.rolbypassrls,"
                                "has_schema_privilege('public','CREATE') AS ddl "
                                "FROM pg_roles r WHERE rolname=current_user"
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
        finally:
            await reader.dispose()
        assert restored == limit and not any(attributes.values())
        write_json(
            output / "day17-canary.json",
            dict(
                version=1,
                profile="local_drill",
                provenance=provenance(),
                readiness_sha256=readiness_digest(),
                fault=windows[0],
                recovered=windows[1],
                connection_limit_restored=restored == limit,
                runtime_superuser=attributes["rolsuper"],
                runtime_bypassrls=attributes["rolbypassrls"],
                runtime_schema_create=attributes["ddl"],
                real_aws_verified=False,
            ),
        )
    finally:
        if limit is not None:
            await set_limit(limit)
        if process is not None and process.poll() is None:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
            try:
                await asyncio.to_thread(process.wait, 5)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 5)
        log.close()
        await admin.dispose()
        write_json(
            output / "day17-canary-diagnostics.json",
            {"completed_windows": [row["phase"] for row in windows], "provenance": provenance()},
        )


def test_zz_readiness_gate() -> None:
    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    result = evaluate(directory)
    assert result["decision"] == "ready_for_local_release"
    write_json(directory / "day17-readiness.json", result)
    verify_readiness(directory)
