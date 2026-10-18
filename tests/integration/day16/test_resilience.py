from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import boto3
import pytest
from sqlalchemy import Table, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from connected_vehicle.remote_command.dispatch_service import (
    RemoteCommandDispatchService,
    RemoteCommandOrderPendingError,
)
from connected_vehicle.remote_command.domain import RemoteCommand, RemoteCommandType
from connected_vehicle.remote_command.event_handler import RemoteCommandRequestedEventHandler
from connected_vehicle.remote_command.persistence.models import RemoteCommandModel
from connected_vehicle.remote_command.service import IssueRemoteCommandService
from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from connected_vehicle.vehicle.persistence.repository import SQLAlchemyVehicleRepository
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    load_runtime_database_settings,
    migration_database_settings,
)
from enterprise_platform.database.engine import build_database_url, create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.recovery import connection_lost, recover_transaction, sqlstate
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.tenant import set_tenant_scope
from enterprise_platform.messaging.serialization import deserialize_event_envelope
from enterprise_platform.runtime.process import run_worker
from scripts.day16_evidence import evidence, verify
from simulators.body_ecu.service import BodyStore
from simulators.vehicle_device.can import precise_command_frame
from tests.integration.day12.test_credential_cloud_contracts import prepare
from tests.support.day16_faults import CommitResponseDropper


async def seed_vehicle(settings: Settings, vehicle: Vehicle) -> None:
    # Provisioning fixtures use management credentials; app remains SELECT-only for vehicles.
    engine = create_database_engine(settings)
    try:
        async with create_session_factory(engine).begin() as session:
            SQLAlchemyVehicleRepository(session).add(vehicle)
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_transaction_faults(local_environment: Settings) -> None:
    engine = create_database_engine(
        migration_database_settings(local_environment).model_copy(
            update={
                "database_lock_timeout_seconds": 0.15,
                "database_statement_timeout_seconds": 4.0,
            }
        )
    )
    table = "day16_" + uuid4().hex
    try:
        async with engine.begin() as connection:
            await connection.execute(text(f"CREATE TABLE {table} (id int PRIMARY KEY, value int)"))
            await connection.execute(text(f"INSERT INTO {table} VALUES (1, 0), (2, 0)"))
        async with engine.connect() as blocker:
            await blocker.execute(text(f"UPDATE {table} SET value=99 WHERE id=1"))
            attempts = 0
            states = []

            async def blocked_write() -> int:
                nonlocal attempts
                attempts += 1
                try:
                    async with engine.begin() as connection:
                        await connection.execute(text(f"UPDATE {table} SET value=3 WHERE id=2"))
                        await connection.execute(text(f"UPDATE {table} SET value=3 WHERE id=1"))
                except DBAPIError as exc:
                    states.append(sqlstate(exc))
                    raise
                return 1

            async def absent() -> int | None:
                return None

            async with asyncio.timeout(5):
                with pytest.raises(DBAPIError):
                    await recover_transaction(blocked_write, absent, base_delay=0.01)
            assert attempts == 3 and states == ["55P03"] * 3
            await blocker.rollback()
        async with engine.connect() as connection:
            assert (
                await connection.execute(text(f"SELECT value FROM {table} ORDER BY id"))
            ).scalars().all() == [0, 0]
        evidence(
            "database-lock-timeout",
            {"bounded_attempts": True, "sqlstate_recorded": True, "no_partial_commit": True},
        )

        barriers = [asyncio.Event(), asyncio.Event()]
        deadlocks: list[str | None] = []

        async def opposite(index: int) -> None:
            first, second = (1, 2) if index == 0 else (2, 1)
            count = 0

            async def operation() -> int:
                nonlocal count
                count += 1
                try:
                    async with engine.begin() as connection:
                        await connection.execute(text("SET LOCAL lock_timeout='3s'"))
                        await connection.execute(
                            text(f"UPDATE {table} SET value=value+1 WHERE id={first}")
                        )
                        if count == 1:
                            barriers[index].set()
                            await barriers[1 - index].wait()
                        await connection.execute(
                            text(f"UPDATE {table} SET value=value+1 WHERE id={second}")
                        )
                except DBAPIError as exc:
                    deadlocks.append(sqlstate(exc))
                    raise
                return 1

            await recover_transaction(operation, absent, base_delay=0.01)

        async with asyncio.timeout(10):
            await asyncio.gather(opposite(0), opposite(1))
        assert deadlocks == ["40P01"]
        async with engine.connect() as connection:
            assert (
                await connection.execute(text(f"SELECT value FROM {table} ORDER BY id"))
            ).scalars().all() == [2, 2]
        evidence(
            "database-deadlock",
            {"actual_deadlock": True, "whole_transaction_retry": True, "no_partial_commit": True},
        )
        administrator = create_database_engine(local_environment)
        try:
            async with engine.connect() as interrupted:
                await interrupted.execute(text(f"UPDATE {table} SET value=99 WHERE id=1"))
                pid = await interrupted.scalar(text("SELECT pg_backend_pid()"))
                async with administrator.begin() as admin:
                    assert await admin.scalar(
                        text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}
                    )
                with pytest.raises(DBAPIError) as lost:
                    await interrupted.execute(text("SELECT 1"))
                assert connection_lost(lost.value)
            async with engine.connect() as fresh:
                assert (
                    await fresh.execute(text(f"SELECT value FROM {table} ORDER BY id"))
                ).scalars().all() == [2, 2]
            evidence(
                "database-disconnect",
                {
                    "backend_terminated": True,
                    "uncommitted_write_rolled_back": True,
                    "fresh_connection_usable": True,
                },
            )
        finally:
            await administrator.dispose()
    finally:
        async with engine.begin() as connection:
            await connection.execute(text(f"DROP TABLE IF EXISTS {table}"))
        await engine.dispose()


@pytest.mark.integration
async def test_commit_response_loss(
    local_environment: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    _, _, settings, _ = await prepare(local_environment, "day16-commit")
    settings = await load_runtime_database_settings(settings, "application")
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(), vin=VIN(uuid4().hex[:17].upper()), tenant_id="day16-commit"
    ).transition_to(VehicleStatus.ACTIVE)
    await seed_vehicle(local_environment, vehicle)
    dropper = CommitResponseDropper(settings.database_host, settings.database_port)
    server = await asyncio.start_server(dropper.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    proxy = create_async_engine(
        build_database_url(settings.model_copy(update={"database_port": port})),
        connect_args={"ssl": False},
        pool_pre_ping=True,
    )
    try:
        service = IssueRemoteCommandService(async_sessionmaker(proxy, expire_on_commit=False))
        key = uuid4().hex
        async with asyncio.timeout(15):
            result = await service.issue(
                vehicle_id=vehicle.id,
                tenant_id=vehicle.tenant_id,
                command_type=RemoteCommandType.LOCK,
                idempotency_key=key,
            )
        assert dropper.dropped.is_set() and result.created is False
        replay = await IssueRemoteCommandService(sessions).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=key,
        )
        assert replay.command.id == result.command.id and not replay.created
        async with sessions() as session:
            await set_tenant_scope(session, vehicle.tenant_id)
            assert await session.scalar(select(func.count()).select_from(RemoteCommandModel)) == 1
        # Administrative observation only: app role deliberately cannot SELECT outbox.
        observer = create_database_engine(local_environment)
        try:
            async with observer.connect() as connection:
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM outbox_events WHERE tenant_id='day16-commit'")
                    )
                    == 1
                )
        finally:
            await observer.dispose()
        evidence(
            "commit-unknown",
            {
                "actual_commit_response_dropped": True,
                "durable_result_reconciled": True,
                "single_command_and_outbox": True,
            },
        )
    finally:
        server.close()
        await dropper.close()
        await server.wait_closed()
        await proxy.dispose()
        await engine.dispose()


@pytest.mark.integration
async def test_outbox_process_crash_and_duplicates(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    document, _, settings, _ = await prepare(local_environment, "day16-outbox")
    app = await load_runtime_database_settings(settings, "application")
    outbox = await load_runtime_database_settings(settings, "outbox")
    worker = await load_runtime_database_settings(settings, "remote-command")
    engines = [create_database_engine(config) for config in (app, outbox, worker)]
    sessions, _, worker_sessions = [create_session_factory(engine) for engine in engines]
    store = SQLAlchemyOutboxStore(create_session_factory(engines[1]))
    client: Any = boto3.client(
        "sqs",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    url = client.create_queue(QueueName="day16-" + uuid4().hex)["QueueUrl"]
    # LocalStack's returned hostname need not resolve on the Windows host.
    from enterprise_platform.messaging.sqs_runtime import normalize_localstack_queue_url

    assert settings.aws_endpoint_url is not None
    url = normalize_localstack_queue_url(url, endpoint_url=settings.aws_endpoint_url)
    published: list[str] = []
    body_path = tmp_path / "body.sqlite"

    class Publisher:
        async def publish(self, command: RemoteCommand) -> None:
            published.append(command.id.value)
            body = BodyStore(body_path)
            try:
                assert (
                    body.execute(
                        precise_command_frame(
                            UUID(command.id.value),
                            1,
                            command.expires_at,
                        )
                    ).data
                    == b"\x00"
                )
            finally:
                body.close()

    try:
        vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(), vin=VIN(uuid4().hex[:17].upper()), tenant_id="day16-outbox"
        ).transition_to(VehicleStatus.ACTIVE)
        await seed_vehicle(local_environment, vehicle)
        service = IssueRemoteCommandService(sessions)
        first = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key="first",
        )
        environment = dict(
            os.environ,
            DAY16_DB_PORT=str(outbox.database_port),
            DAY16_DB_USER=outbox.database_username,
            DAY16_DB_PASSWORD=outbox.database_password.get_secret_value(),
            DAY16_ENDPOINT=str(settings.aws_endpoint_url),
            DAY16_QUEUE_URL=url,
        )
        for point, code in (("before_send", 85), ("after_send", 86)):
            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "tests.support.day16_faults"],
                env=dict(environment, DAY16_CRASH_POINT=point),
                capture_output=True,
                timeout=20,
            )
            assert result.returncode == code, "Crash publisher did not reach its checkpoint"
            await asyncio.sleep(1.1)
        claimed = await store.claim_batch(batch_size=1, lease_seconds=30)
        assert len(claimed) == 1 and claimed[0].attempts == 3
        client.send_message(QueueUrl=url, MessageBody=claimed[0].event_body)
        assert await store.mark_published(
            outbox_id=claimed[0].id, claim_token=claimed[0].claim_token
        )
        messages = client.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)[
            "Messages"
        ]
        assert len(messages) == 2
        execution_crash = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-m", "tests.support.day16_faults"],
            env=dict(
                environment,
                DAY16_DB_USER=worker.database_username,
                DAY16_DB_PASSWORD=worker.database_password.get_secret_value(),
                DAY16_CRASH_POINT="after_execution",
                DAY16_BODY_PATH=str(body_path),
                DAY16_MESSAGE=messages[0]["Body"],
            ),
            capture_output=True,
            timeout=20,
        )
        assert execution_crash.returncode == 87, "Worker did not reach execution crash"
        handler = RemoteCommandRequestedEventHandler(
            RemoteCommandDispatchService(worker_sessions, Publisher())
        )
        for message in messages:
            await handler(deserialize_event_envelope(message["Body"]))
            client.delete_message(QueueUrl=url, ReceiptHandle=message["ReceiptHandle"])
        assert published == [first.command.id.value]
        restarted = BodyStore(body_path)
        try:
            assert restarted.db.execute("SELECT count(*) FROM executions").fetchone()[0] == 1
            assert restarted.db.execute("SELECT locked FROM body").fetchone()[0] == 1
        finally:
            restarted.close()
        evidence(
            "outbox-crash",
            {
                "before_send_process_crash": True,
                "after_send_process_crash": True,
                "lease_reclaimed": True,
                "duplicate_delivery_single_dispatch": True,
                "post_execution_crash_single_business_effect": True,
            },
        )
        second = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.UNLOCK,
            idempotency_key="second",
        )
        from connected_vehicle.remote_command.events import create_remote_command_requested_event

        with pytest.raises(RemoteCommandOrderPendingError):
            await handler(create_remote_command_requested_event(second.command))
        await handler(create_remote_command_requested_event(first.command))
        assert published == [first.command.id.value]
        async with worker_sessions() as session:
            await set_tenant_scope(session, vehicle.tenant_id)
            assert (
                await session.scalar(
                    select(RemoteCommandModel.status).where(
                        RemoteCommandModel.id == first.command.id.value
                    )
                )
                == "sent"
            )
        evidence(
            "duplicate-order",
            {
                "duplicate_suppressed": True,
                "out_of_order_rejected": True,
                "no_state_regression": True,
            },
        )
        old = (await store.claim_batch(batch_size=1, lease_seconds=1))[0]
        expired = datetime.now(UTC) + timedelta(seconds=2)
        assert not await store.mark_published(
            outbox_id=old.id, claim_token=old.claim_token, published_at=expired
        )
        # Expiry alone fences every update, even before another worker reclaims it.
        await asyncio.sleep(1.1)
        assert not await store.schedule_retry(
            outbox_id=old.id, claim_token=old.claim_token, available_at=expired
        )
        new = (await store.claim_batch(batch_size=1, now=expired, lease_seconds=30))[0]
        assert old.claim_token != new.claim_token
        assert not await store.schedule_retry(
            outbox_id=old.id, claim_token=old.claim_token, available_at=expired
        )
        assert not await store.mark_failed(
            outbox_id=old.id,
            claim_token=old.claim_token,
            failed_at=expired,
            failure_code="retry_exhausted",
        )
        assert await store.mark_published(
            outbox_id=new.id, claim_token=new.claim_token, published_at=expired
        )
        evidence(
            "lease-fencing",
            {
                "expired_publish_rejected": True,
                "stale_token_all_updates_rejected": True,
                "current_owner_succeeds": True,
            },
        )
    finally:
        client.delete_queue(QueueUrl=url)
        client.close()
        for engine in engines:
            await engine.dispose()


@pytest.mark.integration
async def test_credential_fences_and_audit_interruption(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.integration.day12.test_credential_cloud_contracts import (
        test_external_localstack_version_competition_during_real_management_lock,
    )
    from tests.integration.day12.test_credential_lifecycle import (
        test_postgresql_localstack_credential_lifecycle,
    )

    await test_external_localstack_version_competition_during_real_management_lock(
        local_environment, tmp_path / "competition", monkeypatch
    )
    evidence(
        "credential-fencing",
        {
            "foreign_pending_preserved": True,
            "foreign_current_preserved": True,
            "no_stale_password_overwrite": True,
        },
    )
    await test_postgresql_localstack_credential_lifecycle(
        local_environment, tmp_path / "lifecycle", monkeypatch
    )
    evidence(
        "audit-interruption",
        {
            "checkpoint_failure_recoverable": True,
            "archive_tampering_rejected": True,
            "repeated_recovery_safe": True,
        },
    )


@pytest.mark.integration
async def test_dependency_and_monitor_outages(
    local_environment: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = migration_database_settings(local_environment)
    engine = create_database_engine(settings)
    # A deterministic real TCP refusal, isolated from the dependency container.
    listener = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    bad_port = listener.sockets[0].getsockname()[1]
    listener.close()
    await listener.wait_closed()
    unavailable = create_database_engine(settings.model_copy(update={"database_port": bad_port}))
    stop = asyncio.Event()
    attempts = 0
    sleeps: list[float] = []
    started = asyncio.get_running_loop().time()

    async def operation() -> int:
        nonlocal attempts
        attempts += 1
        sleeps.append(asyncio.get_running_loop().time() - started)
        target = unavailable if attempts < 4 else engine
        async with target.begin() as connection:
            assert await connection.scalar(text("SELECT 1")) == 1
        stop.set()
        return 1

    def broken_monitor(*args: object, **kwargs: object) -> None:
        raise ConnectionError("monitor unavailable")

    monkeypatch.setattr("enterprise_platform.runtime.process.logger.log", broken_monitor)
    try:
        async with asyncio.timeout(10):
            await run_worker(
                operation,
                stop=stop,
                poll_interval=0.01,
                error_delay=0.1,
                shutdown_timeout=1,
                operation_timeout=2,
            )
        assert attempts == 4 and sleeps[-1] >= 0.35
        evidence(
            "database-outage",
            {
                "connection_failure_detected": True,
                "bounded_exponential_backoff": True,
                "recovered_on_next_connection": True,
            },
        )
        evidence(
            "monitor-outage",
            {"telemetry_failure_isolated": True, "database_transaction_succeeds": True},
        )
    finally:
        await unavailable.dispose()
        await engine.dispose()


@pytest.mark.integration
async def test_existing_claim_lease_regressions(
    local_environment: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.integration.reliability import test_outbox_claim_lease as cases

    monkeypatch.setattr(cases, "get_settings", lambda: local_environment)
    schema = "day16_lease_" + uuid4().hex
    administrator = create_database_engine(local_environment)
    isolated = administrator.execution_options(schema_translate_map={None: schema})
    try:
        async with administrator.begin() as connection:
            await connection.execute(text(f"CREATE SCHEMA {schema}"))
        async with isolated.begin() as connection:
            table = OutboxEventModel.__table__
            assert isinstance(table, Table)
            await connection.run_sync(table.create)
        monkeypatch.setattr(
            cases,
            "create_database_engine",
            lambda settings: create_database_engine(settings).execution_options(
                schema_translate_map={None: schema}
            ),
        )
        await cases.test_two_workers_claim_disjoint_batches_with_skip_locked()
        await cases.test_expired_lease_is_reclaimed_and_stale_token_is_fenced()
        await cases.test_scheduled_retry_is_not_claimed_before_available_at()
    finally:
        async with administrator.begin() as connection:
            await connection.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
        await administrator.dispose()


def test_zz_recovery_evidence_gate() -> None:
    assert (
        json.loads(verify(Path(os.environ["RUNTIME_EVIDENCE_DIR"])).read_text())["status"]
        == "passed"
    )
