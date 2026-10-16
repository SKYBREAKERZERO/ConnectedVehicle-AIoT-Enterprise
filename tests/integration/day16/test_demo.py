"""Reviewable local recovery exercise: real faults, persistent state and Prometheus."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import boto3
import pytest
from prometheus_client import start_http_server
from sqlalchemy import text

from connected_vehicle.device_data import CommandReport
from connected_vehicle.device_service import DeviceDataService
from connected_vehicle.remote_command.dispatch_service import RemoteCommandDispatchService
from connected_vehicle.remote_command.domain import RemoteCommand, RemoteCommandType
from connected_vehicle.remote_command.event_handler import RemoteCommandRequestedEventHandler
from connected_vehicle.remote_command.service import IssueRemoteCommandService
from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from database.credential_audit import save_checkpoint, verify_archive_chain
from database.credential_rotation import password_manager, rotate
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.messaging.serialization import deserialize_event_envelope
from enterprise_platform.messaging.sqs_runtime import normalize_localstack_queue_url
from enterprise_platform.observability.context import bind_observability_context
from enterprise_platform.observability.recovery import (
    RecoveryMonitor,
    monitoring_session,
    observe_recovery,
    recovery_scope,
)
from scripts.day16_evidence import evidence, provenance, validate_demo, write_record
from simulators.body_ecu.service import BodyStore
from simulators.vehicle_device.can import precise_command_frame
from tests.e2e.test_independent_runtimes import docker
from tests.integration.day12.test_credential_cloud_contracts import prepare
from tests.integration.day16.test_resilience import seed_vehicle


def api(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.loads(response.read())


async def query_metrics(url: str, component: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"query": 'vehicle_recovery_transitions_total{component="' + component + '"}'}
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            result = await asyncio.to_thread(api, url + "/api/v1/query?" + query)
            rows = result["data"]["result"]
            if any(row["metric"]["state"] == "RECOVERED" for row in rows):
                return [
                    {"state": row["metric"]["state"], "value": float(row["value"][1])}
                    for row in rows
                ]
        except (OSError, KeyError):
            pass
        await asyncio.sleep(0.2)
    raise AssertionError("Prometheus did not scrape the recovered operation")


async def status(settings: Settings, command_id: str) -> dict[str, Any]:
    observer = create_database_engine(settings)
    try:
        async with observer.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text("""SELECT c.status,
                (SELECT count(*) FROM outbox_events o
                    WHERE o.event_id=:event) AS outbox,
                (SELECT count(*) FROM command_reports r WHERE r.command_id=c.id) AS reports
                FROM remote_commands c WHERE c.id=:id"""),
                        {"id": command_id, "event": "remote-command:" + command_id + ":requested"},
                    )
                )
                .mappings()
                .one()
            )
            return dict(row)
    finally:
        await observer.dispose()


async def audit_proof(
    settings: Settings,
    targets: list[Any],
    client: Any,
    folder: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    async with password_manager(settings, targets) as backend:
        path = await rotate(
            settings,
            targets,
            {target.role: "demo-" + uuid4().hex for target in targets},
            client,
            backend,
            directory=folder,
        )
    record = json.loads(path.read_text())
    phase_before = record["phase"]
    for _ in range(140):
        save_checkpoint(path, record)
    assert verify_archive_chain(path, record) >= 2
    before = path.read_bytes()
    hashes = {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest()
        for item in (folder / "audit").glob("*.json")
    }
    sequence = record["events"][-1]["sequence"]

    def interrupted(*args: object, **kwargs: object) -> None:
        raise OSError("injected checkpoint interruption")

    with monkeypatch.context() as patch:
        patch.setattr("database.credential_audit.os.replace", interrupted)
        with pytest.raises(OSError):
            save_checkpoint(path, record)
    assert before == path.read_bytes()
    save_checkpoint(path, record)
    assert all(
        hashlib.sha256((folder / "audit" / name).read_bytes()).hexdigest() == digest
        for name, digest in hashes.items()
    )
    assert verify_archive_chain(path, record) >= 2
    return {
        "phase_before": phase_before,
        "phase_after": record["phase"],
        "sequence_before": sequence,
        "sequence_after": record["events"][-1]["sequence"],
        "archives_before": hashes,
        "archives_after": {
            name: hashlib.sha256((folder / "audit" / name).read_bytes()).hexdigest()
            for name in hashes
        },
        "checkpoint_unchanged_on_failure": True,
        "chain_verified": True,
        "checkpoint": {
            key: record[key]
            for key in ("operation_id", "phase", "audit_offset", "audit_archive_sha256", "events")
        },
        "segments": [
            {
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
                "record": json.loads(item.read_text()),
            }
            for item in sorted((folder / "audit").glob("*.json"))
        ],
    }


async def lock_case(
    settings: Settings, admin: Settings, monitor: RecoveryMonitor, prom: str
) -> dict[str, Any]:
    runtime = await load_runtime_database_settings(settings, "application")
    engine = create_database_engine(
        runtime.model_copy(update={"database_lock_timeout_seconds": 0.15})
    )
    blocker_engine = create_database_engine(admin)
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(), vin=VIN(uuid4().hex[:17].upper()), tenant_id="day16-demo"
    ).transition_to(VehicleStatus.ACTIVE)
    await seed_vehicle(admin, vehicle)
    key, fault = uuid4().hex, uuid4().hex
    operation = hashlib.sha256(
        "\0".join((vehicle.tenant_id, vehicle.id.value, key)).encode()
    ).hexdigest()
    started = time.monotonic()
    try:
        with (
            monitoring_session(monitor),
            recovery_scope("database", operation_id=operation, fault_id=fault),
        ):
            async with blocker_engine.connect() as blocker:
                await blocker.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                    {"key": vehicle.tenant_id + ":" + vehicle.id.value},
                )
                service = IssueRemoteCommandService(create_session_factory(engine))
                task = asyncio.create_task(
                    service.issue(
                        vehicle_id=vehicle.id,
                        tenant_id=vehicle.tenant_id,
                        command_type=RemoteCommandType.LOCK,
                        idempotency_key=key,
                    )
                )
                try:
                    async with asyncio.timeout(5):
                        while not any(
                            row["operation_id"] == operation and row["state"] == "RETRY"
                            for row in monitor.snapshot()
                        ):
                            await asyncio.sleep(0.01)
                    print(
                        f"FAULT lock_timeout operation={operation}; RETRY observed, releasing lock",
                        flush=True,
                    )
                    await blocker.rollback()
                    result = await asyncio.wait_for(task, 5)
                finally:
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            after = await status(admin, result.command.id.value)
            assert after == {"status": "requested", "outbox": 1, "reports": 0}
            replay = await service.issue(
                vehicle_id=vehicle.id,
                tenant_id=vehicle.tenant_id,
                command_type=RemoteCommandType.LOCK,
                idempotency_key=key,
            )
            assert replay.command.id == result.command.id and not replay.created
        rows = [row for row in monitor.snapshot() if row["operation_id"] == operation]
        assert any(row["sqlstate"] == "55P03" for row in rows)
        return {
            "case": "lock",
            "operation_id": operation,
            "fault_id": fault,
            "events": rows,
            "after": after,
            "elapsed_seconds": time.monotonic() - started,
            "prometheus_samples": await query_metrics(prom, "database"),
        }
    finally:
        await engine.dispose()
        await blocker_engine.dispose()


async def worker_case(
    settings: Settings, admin: Settings, folder: Path, monitor: RecoveryMonitor, prom: str
) -> dict[str, Any]:
    assert settings.database_tenant_id is not None
    runtime = [
        await load_runtime_database_settings(settings, "application"),
        await load_runtime_database_settings(settings, "outbox"),
        await load_runtime_database_settings(settings, "remote-command"),
    ]
    engines = [create_database_engine(config) for config in runtime]
    sessions, outbox_sessions, worker_sessions = [
        create_session_factory(engine) for engine in engines
    ]
    client: Any = boto3.client(
        "sqs",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    assert settings.aws_endpoint_url is not None
    queue = normalize_localstack_queue_url(
        client.create_queue(QueueName="demo-" + uuid4().hex)["QueueUrl"],
        endpoint_url=settings.aws_endpoint_url,
    )
    body_path = folder / "body.sqlite"
    operation, fault = uuid4().hex, uuid4().hex
    started = time.monotonic()

    class Publisher:
        async def publish(self, command: RemoteCommand) -> None:
            body = BodyStore(body_path)
            try:
                assert (
                    body.execute(
                        precise_command_frame(UUID(command.id.value), 1, command.expires_at)
                    ).data
                    == b"\x00"
                )
            finally:
                body.close()

    async def crash(point: str, environment: dict[str, str], code: int) -> None:
        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-m", "tests.support.day16_faults"],
            env=dict(environment, DAY16_CRASH_POINT=point),
            capture_output=True,
            timeout=20,
        )
        assert result.returncode == code, "Crash checkpoint not reached"
        observe_recovery("FAULT_DETECTED", 1)
        observe_recovery("CLASSIFIED", 1)
        observe_recovery("RETRY", 1)
        print(
            f"FAULT {point} exit={code} operation={operation}; restarting from durable state",
            flush=True,
        )

    try:
        vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(),
            vin=VIN(uuid4().hex[:17].upper()),
            tenant_id=settings.database_tenant_id,
        ).transition_to(VehicleStatus.ACTIVE)
        await seed_vehicle(admin, vehicle)
        issued = await IssueRemoteCommandService(sessions).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=uuid4().hex,
        )
        environment = dict(
            os.environ,
            DAY16_DB_PORT=str(settings.database_port),
            DAY16_DB_USER=runtime[1].database_username,
            DAY16_DB_PASSWORD=runtime[1].database_password.get_secret_value(),
            DAY16_ENDPOINT=settings.aws_endpoint_url,
            DAY16_QUEUE_URL=queue,
        )
        with (
            monitoring_session(monitor),
            recovery_scope("worker", operation_id=operation, fault_id=fault),
        ):
            observe_recovery("RUNNING")
            await crash("after_send", environment, 86)
            await asyncio.sleep(1.1)
            store = SQLAlchemyOutboxStore(outbox_sessions)
            # The lock case's Outbox belongs to the same tenant: mark it separately
            # before starting this worker exercise so only the selected command is claimed.
            claimed = await store.claim_batch(batch_size=1, lease_seconds=30)
            assert (
                len(claimed) == 1
                and claimed[0].event_id
                == "remote-command:" + issued.command.id.value + ":requested"
            )
            client.send_message(QueueUrl=queue, MessageBody=claimed[0].event_body)
            assert await store.mark_published(
                outbox_id=claimed[0].id, claim_token=claimed[0].claim_token
            )
            messages = client.receive_message(
                QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=2
            )["Messages"]
            assert len(messages) == 2
            await crash(
                "after_execution",
                dict(
                    environment,
                    DAY16_DB_USER=runtime[2].database_username,
                    DAY16_DB_PASSWORD=runtime[2].database_password.get_secret_value(),
                    DAY16_MESSAGE=messages[0]["Body"],
                    DAY16_BODY_PATH=str(body_path),
                ),
                87,
            )
            handler = RemoteCommandRequestedEventHandler(
                RemoteCommandDispatchService(worker_sessions, Publisher())
            )
            for message in messages:
                await handler(deserialize_event_envelope(message["Body"]))
                client.delete_message(QueueUrl=queue, ReceiptHandle=message["ReceiptHandle"])
            device = DeviceDataService(sessions)
            for state in ("acknowledged", "succeeded"):
                report = CommandReport.model_validate(
                    {"event_id": str(uuid4()), "status": state, "occurred_at": datetime.now(UTC)}
                )
                assert (
                    await device.report(
                        tenant=vehicle.tenant_id,
                        vehicle=vehicle.id.value,
                        command_id=issued.command.id.value,
                        report=report,
                    )
                    == state
                )
                assert (
                    await device.report(
                        tenant=vehicle.tenant_id,
                        vehicle=vehicle.id.value,
                        command_id=issued.command.id.value,
                        report=report,
                    )
                    == state
                )
            after = await status(admin, issued.command.id.value)
            assert after == {"status": "succeeded", "outbox": 1, "reports": 2}
            body = BodyStore(body_path)
            try:
                executions = body.db.execute("SELECT count(*) FROM executions").fetchone()[0]
                locked = body.db.execute("SELECT locked FROM body").fetchone()[0]
            finally:
                body.close()
            assert executions == 1 and locked == 1
            observe_recovery("VERIFY", 3)
            observe_recovery("RECOVERED", 3)
        return {
            "case": "worker",
            "operation_id": operation,
            "fault_id": fault,
            "events": [row for row in monitor.snapshot() if row["operation_id"] == operation],
            "after": after,
            "device_executions": executions,
            "device_locked": locked,
            "elapsed_seconds": time.monotonic() - started,
            "prometheus_samples": await query_metrics(prom, "worker"),
        }
    finally:
        client.delete_queue(QueueUrl=queue)
        client.close()
        for engine in engines:
            await engine.dispose()


@pytest.mark.integration
async def test_reviewable_recovery_demonstration(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    _, targets, settings, client = await prepare(local_environment, "day16-demo")
    monitor = RecoveryMonitor()
    exporter, thread = start_http_server(0, addr="0.0.0.0", registry=monitor.registry)
    config = tmp_path / "prometheus.yml"
    config.write_text(
        "global:\n  scrape_interval: 1s\nscrape_configs:\n"
        "  - job_name: recovery-demo\n    static_configs:\n"
        "      - targets: ['host.docker.internal:" + str(exporter.server_port) + "']\n",
        encoding="utf-8",
    )
    name = "vehicle-day16-prometheus-" + uuid4().hex[:10]
    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    selected = os.environ.get("DAY16_DEMO_CASE", "all")
    proof: dict[str, Any] = {
        "version": 1,
        "provenance": provenance(),
        "cases": [],
        "real_aws_verified": False,
    }
    try:
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "cv.day16.run=" + os.environ.get("DAY16_DEMO_OWNER", uuid4().hex),
            "--add-host",
            "host.docker.internal:host-gateway",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-p",
            "127.0.0.1::9090",
            "-v",
            f"{config}:/etc/prometheus/prometheus.yml:ro",
            "prom/prometheus:v3.5.0",
        )
        prom = "http://127.0.0.1:" + docker("port", name, "9090").split(":")[-1]
        print("Recovery demo Prometheus: " + prom, flush=True)
        proof["audit"] = await audit_proof(
            settings, targets, client, tmp_path / "credential", monkeypatch
        )
        with bind_observability_context(
            request_id=uuid4().hex, correlation_id=uuid4().hex, trace_id=uuid4().hex
        ):
            if selected in {"all", "lock"}:
                proof["cases"].append(await lock_case(settings, local_environment, monitor, prom))
            if selected in {"all", "worker"}:
                # Use a separate pinned tenant for worker claims; the lock exercise
                # deliberately leaves its command requested for state inspection.
                _, _, worker_settings, _ = await prepare(local_environment, "day16-worker-demo")
                proof["cases"].append(
                    await worker_case(worker_settings, local_environment, tmp_path, monitor, prom)
                )
        validate_demo(proof, required_cases={"lock", "worker"} if selected == "all" else {selected})
        write_record(directory, "demo-proof", proof)
        if selected == "all":
            evidence(
                "recovery-demonstration",
                {
                    "correlated_lifecycle": True,
                    "prometheus_scraped": True,
                    "durable_state_verified": True,
                    "audit_history_preserved": True,
                },
            )
        print(
            "RECOVERED: database, device effects, audit history and Prometheus samples verified",
            flush=True,
        )
    finally:
        write_record(
            directory,
            "demo-diagnostics",
            {
                "provenance": provenance(),
                "events": monitor.snapshot(),
                "completed_cases": [case["case"] for case in proof["cases"]],
            },
        )
        await asyncio.to_thread(exporter.shutdown)
        exporter.server_close()
        thread.join(timeout=2)
        docker("rm", "-f", name)
