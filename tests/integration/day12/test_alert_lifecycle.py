"""Real SQLite/PostgreSQL collection and real Prometheus/Alertmanager delivery."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy import text

from database.provision_tenant_local import provision_monitor
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine
from simulators.vehicle_device.store import Store
from tests.e2e.test_independent_runtimes import ROOT, docker
from tests.integration.day12.conftest import evidence, migration_environment
from tests.unit.test_device_simulator import payload, settings


def api(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.loads(response.read())  # type: ignore[no-any-return]


async def alert_state(url: str, name: str, firing: bool) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        alerts = api(url + "/api/v1/alerts")["data"]["alerts"]
        matches = [value for value in alerts if value["labels"]["alertname"] == name]
        if firing and matches and matches[0]["state"] == "firing":
            return dict(matches[0])
        if not firing and not matches:
            return {}
        await asyncio.sleep(0.2)
    raise AssertionError(f"Alert {name} did not reach {'firing' if firing else 'resolved'}")


async def webhook(path: Path, name: str, status: str, active_at: str) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        for line in lines:
            value = json.loads(line)
            for alert in value["payload"]["alerts"]:
                delta = (
                    datetime.fromisoformat(alert["startsAt"]) - datetime.fromisoformat(active_at)
                ).total_seconds()
                same_instance = -0.001 <= delta <= 15 if status == "firing" else abs(delta) < 0.001
                if (
                    alert["labels"]["alertname"] == name
                    and alert["status"] == status
                    and same_instance
                ):
                    return {
                        "received_at": value["received_at"],
                        "status": status,
                        "starts_at": alert["startsAt"],
                        "ends_at": alert["endsAt"],
                    }
        await asyncio.sleep(0.2)
    raise AssertionError(f"Webhook {name}/{status} was not delivered")


@pytest.mark.integration
async def test_five_real_metric_alerts_firing_webhook_resolved(
    local_environment: Settings,
    tmp_path: Path,
) -> None:
    environment = migration_environment(local_environment)
    environment.pop("DATABASE_TENANT_ID", None)
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=environment,
        check=True,
        capture_output=True,
    )
    monitor = await provision_monitor(local_environment)
    device = settings(tmp_path)
    store = Store(device.database, max_ledger_records=10)
    store.bind_identity(device.tenant_id, str(device.vehicle_id))
    state = tmp_path / "state"
    state.mkdir()
    config_path = tmp_path / "collector.json"
    config: dict[str, Any] = {
        "endpoint": local_environment.aws_endpoint_url,
        "secret_id": monitor["secret_id"],
        "devices": [{"path": str(device.database), "capacity": 10}],
    }

    def write_config() -> None:
        temporary = config_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(config), encoding="utf-8")
        os.replace(temporary, config_path)

    write_config()
    prefix = "vehicle-day12-monitor-" + uuid4().hex[:10]
    containers: list[str] = []
    collector: subprocess.Popen[bytes] | None = None
    engine = create_database_engine(local_environment)
    log = (tmp_path / "collector.log").open("wb")
    rows = []
    try:
        docker("network", "create", prefix)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW
        collector = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "scripts.local_monitor",
                "collect",
                "--directory",
                str(state),
                "--config",
                str(config_path),
            ],
            stdout=log,
            stderr=log,
            creationflags=creationflags,
        )
        for _ in range(100):
            if (state / "health.json").exists() and json.loads((state / "health.json").read_text())[
                "success"
            ]:
                break
            assert collector.poll() is None
            await asyncio.sleep(0.2)
        else:
            raise AssertionError("Collector did not collect real DB/SQLite metrics")
        for service, port, image, arguments in (
            (
                "exporter",
                9000,
                "python:3.12-alpine",
                ["python", "/app/monitor.py", "exporter", "--directory", "/state"],
            ),
            (
                "receiver",
                9001,
                "python:3.12-alpine",
                [
                    "python",
                    "/app/monitor.py",
                    "receiver",
                    "--directory",
                    "/state",
                    "--port",
                    "9001",
                ],
            ),
            ("alertmanager", 9093, "prom/alertmanager:v0.28.1", []),
            ("prometheus", 9090, "prom/prometheus:v3.5.0", []),
        ):
            name = prefix + "-" + service
            ownership: list[str] = []
            if sys.platform != "win32" and service in {"exporter", "receiver"}:
                ownership = ["--user", f"{os.getuid()}:{os.getgid()}"]
            mounts = [
                "-v",
                f"{state}:/state",
                "-v",
                f"{ROOT / 'scripts/local_monitor.py'}:/app/monitor.py:ro",
            ]
            if service == "alertmanager":
                mounts = [
                    "-v",
                    f"{ROOT / 'infra/observability/alertmanager.yml'}"
                    ":/etc/alertmanager/alertmanager.yml:ro",
                ]
            if service == "prometheus":
                mounts = [
                    "-v",
                    f"{ROOT / 'infra/observability/local-prometheus.yml'}"
                    ":/etc/prometheus/prometheus.yml:ro",
                    "-v",
                    f"{ROOT / 'infra/observability/alerts.yml'}:/etc/prometheus/alerts.yml:ro",
                    "-v",
                    f"{ROOT / 'infra/observability/day17-slo.yml'}"
                    ":/etc/prometheus/day17-slo.yml:ro",
                ]
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                prefix,
                "--network-alias",
                service,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                *ownership,
                "-p",
                f"127.0.0.1::{port}",
                *mounts,
                image,
                *arguments,
            )
            containers.append(name)
        url = "http://127.0.0.1:" + docker("port", containers[-1], "9090").split(":")[-1]
        for _ in range(100):
            try:
                if api(url + "/api/v1/targets")["data"]["activeTargets"][0]["health"] == "up":
                    break
            except (OSError, IndexError):
                pass
            await asyncio.sleep(0.2)
        else:
            raise AssertionError("Prometheus did not scrape the real exporter")

        async def capture(name: str) -> str:
            firing = await alert_state(url, name, True)
            delivered = await webhook(state / "alerts.jsonl", name, "firing", firing["activeAt"])
            rows.append({"alert": name, "prometheus": "FIRING", "webhook_firing": delivered})
            return str(delivered["starts_at"])

        async def resolved(name: str, active_at: str) -> None:
            await alert_state(url, name, False)
            rows[-1]["webhook_resolved"] = await webhook(
                state / "alerts.jsonl", name, "resolved", active_at
            )

        store.accept(payload(device))
        ack = store.pending_report()
        assert ack is not None
        store.report_result(ack["sequence"], 401, 7)
        started = await capture("DeviceAuthenticationBlocked")
        store.requeue_report(
            event_id=json.loads(ack["payload"])["event_id"],
            operation_id=str(uuid4()),
            actor="local-operator",
            reason="repaired injected authentication failure",
            tenant_id=device.tenant_id,
            vehicle_id=str(device.vehicle_id),
        )
        store.report_result(ack["sequence"], 200, 0)
        await resolved("DeviceAuthenticationBlocked", started)

        vehicle_id, command_id = str(uuid4()), str(uuid4())
        async with engine.begin() as connection:
            await connection.execute(
                text("""INSERT INTO vehicles VALUES
                (:id,'D12ALERT123456789','alert-tenant','active',now(),now())"""),
                {"id": vehicle_id},
            )
            await connection.execute(
                text("""INSERT INTO remote_commands
                (id,vehicle_id,tenant_id,command_type,status,idempotency_key,created_at,updated_at,expires_at)
                VALUES (:id,:vehicle,'alert-tenant','lock','sent','alert-probe',
                now()-interval '10 minutes',now(),now()-interval '5 minutes')"""),
                {"id": command_id, "vehicle": vehicle_id},
            )
        started = await capture("VehicleCommandOrderStalled")
        # Remove only this dedicated test fixture; never infer success for an unknown execution.
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM remote_commands WHERE id=:id"), {"id": command_id}
            )
            await connection.execute(text("DELETE FROM vehicles WHERE id=:id"), {"id": vehicle_id})
        await resolved("VehicleCommandOrderStalled", started)

        for _ in range(7):
            store.accept(payload(device))
            report = store.pending_report()
            assert report is not None
            store.report_result(report["sequence"], 200, 0)
        started = await capture("DeviceLedgerCapacityWarning")
        store.max_ledger_records = 20
        config["devices"][0]["capacity"] = 20
        write_config()
        await resolved("DeviceLedgerCapacityWarning", started)

        delayed = payload(device)
        with patch("simulators.vehicle_device.store.datetime") as clock:
            clock.now.return_value = datetime.now(UTC) - timedelta(minutes=10)
            store.accept(delayed)
        started = await capture("RuntimeReportDeliveryStalled")
        report = store.pending_report()
        assert report is not None
        store.report_result(report["sequence"], 200, 0)
        await resolved("RuntimeReportDeliveryStalled", started)

        config["devices"][0]["path"] = str(tmp_path / "missing-ledger.sqlite")
        write_config()
        started = await capture("RuntimeCollectorUnavailable")
        config["devices"][0]["path"] = str(device.database)
        write_config()
        await resolved("RuntimeCollectorUnavailable", started)
        assert len(rows) == 5
        evidence(
            "12c-alert-lifecycle",
            {
                "scope": "local-only",
                "collection": "real SQLite/PostgreSQL",
                "faults": "dedicated injected fixtures",
                "alerts": rows,
            },
        )
    finally:
        if collector is not None:
            collector.terminate()
            collector.wait(timeout=15)
        log.close()
        store.close()
        await engine.dispose()
        for name in reversed(containers):
            docker("rm", "-f", name)
        docker("network", "rm", prefix)
