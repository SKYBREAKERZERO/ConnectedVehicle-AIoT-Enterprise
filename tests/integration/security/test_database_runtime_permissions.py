from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.device_data import CommandReport, TelemetrySample, TelemetrySampleModel
from connected_vehicle.device_service import DeviceDataService
from connected_vehicle.remote_command.dispatch_service import (
    RemoteCommandDispatchCommandNotFoundError,
    RemoteCommandDispatchService,
    RemoteCommandOrderPendingError,
)
from connected_vehicle.remote_command.domain import RemoteCommandType
from connected_vehicle.remote_command.events import create_remote_command_requested_event
from connected_vehicle.remote_command.persistence.models import RemoteCommandModel
from connected_vehicle.remote_command.service import IssueRemoteCommandService
from connected_vehicle.remote_command.wire_contracts import RequestedPayload
from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from connected_vehicle.vehicle.persistence.repository import SQLAlchemyVehicleRepository
from database.dlq_operations import redrive, redrive_status
from database.operations import reconcile, replay_outbox, timeout_commands
from database.provision_runtime_credentials import SQLDriver, provision
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.base import Base
from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.operations import OperatorActionModel
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.tenant import set_tenant_scope
from enterprise_platform.errors.base import ResourceNotFoundError
from enterprise_platform.messaging.exceptions import InvalidMessageError
from tests.integration.day12.conftest import evidence


@pytest.mark.integration
async def test_real_postgres_runtime_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    # Dedicated container: never revoke grants or change passwords in the development DB.
    name = f"vehicle-grants-test-{uuid4().hex[:12]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-e",
            "POSTGRES_PASSWORD=test-admin",
            "-p",
            "127.0.0.1::5432",
            "postgres:16-alpine",
        ],
        check=True,
        capture_output=True,
    )
    engines = []
    try:
        port = int(
            subprocess.check_output(["docker", "port", name, "5432"], text=True)
            .strip()
            .split(":")[-1]
        )
        settings = Settings.model_construct(
            database_host="127.0.0.1",
            database_port=port,
            database_name="postgres",
            database_username="postgres",
            database_password=SecretStr("test-admin"),
        )
        admin = create_database_engine(settings)
        engines.append(admin)
        for attempt in range(100):
            try:
                async with admin.connect() as connection:
                    await connection.execute(text("SELECT 1"))
                break
            except (OSError, DBAPIError):
                if attempt == 99:
                    raise
                await asyncio.sleep(0.2)
        async with admin.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            raw = await connection.get_raw_connection()
            driver = cast(SQLDriver, raw.driver_connection)
            sql = Path("database/runtime-grants.sql").read_text()
            await driver.execute(sql)
            await driver.execute(sql)  # Idempotent grants, including column privilege reset.
        users = ["app_user", "outbox_worker", "remote_command_worker"]
        passwords = {user: f"test-{user}'special:chars" for user in users}
        for user, password in passwords.items():
            monkeypatch.setenv(f"{user.upper()}_PASSWORD", password)
        writer = Mock()
        with patch("database.provision_runtime_credentials.AWSClientFactory") as factory:
            factory.return_value.secrets_manager.return_value = writer
            await provision(
                settings.model_copy(
                    update={
                        "migration_database_username": "postgres",
                        "migration_database_password": SecretStr("test-admin"),
                    }
                )
            )
        assert writer.put_secret_value.call_count == 3
        for call in writer.put_secret_value.call_args_list:
            payload = json.loads(call.kwargs["SecretString"])
            assert payload["password"] == passwords[payload["username"]]

        sessions = {}
        for user in ["app_user", "outbox_worker", "remote_command_worker"]:
            engine = create_database_engine(
                settings.model_copy(
                    update={
                        "database_username": user,
                        "database_password": SecretStr(passwords[user]),
                    }
                )
            )
            engines.append(engine)
            runtime = next(runtime for runtime, name in DATABASE_USERS.items() if name == user)
            await verify_runtime_database_security(engine, runtime)
            sessions[user] = create_session_factory(engine)
        with pytest.raises(RuntimeError, match="Unsafe runtime database role"):
            await verify_runtime_database_security(admin, "application")
        # Startup contracts detect privilege drift and missing RLS on real PostgreSQL.
        for attribute in ("SUPERUSER", "BYPASSRLS"):
            async with admin.begin() as connection:
                await connection.execute(text(f"ALTER ROLE app_user {attribute}"))
            try:
                with pytest.raises(RuntimeError, match="Unsafe runtime database role"):
                    await verify_runtime_database_security(engines[1], "application")
            finally:
                async with admin.begin() as connection:
                    await connection.execute(text(f"ALTER ROLE app_user NO{attribute}"))
        async with admin.begin() as connection:
            await connection.execute(text("ALTER TABLE vehicles DISABLE ROW LEVEL SECURITY"))
        try:
            with pytest.raises(RuntimeError, match="Unsafe runtime database schema"):
                await verify_runtime_database_security(engines[1], "application")
        finally:
            async with admin.begin() as connection:
                await connection.execute(text("ALTER TABLE vehicles ENABLE ROW LEVEL SECURITY"))
        # Drift of expression, WITH CHECK, role scope, command scope and helper body.
        drifts = [
            "ALTER POLICY tenant_guard ON vehicles USING (true)",
            "ALTER POLICY tenant_guard ON vehicles WITH CHECK (true)",
            "ALTER POLICY tenant_guard ON vehicles TO app_user",
            "DROP POLICY runtime_access ON vehicles; "
            "CREATE POLICY runtime_access ON vehicles FOR SELECT USING (true)",
            "CREATE POLICY surprise_access ON vehicles USING (true)",
            "CREATE OR REPLACE FUNCTION public.runtime_tenant_binding() RETURNS text "
            "LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog "
            "AS $$ SELECT NULL::text $$",
        ]
        for drift in drifts:
            async with admin.begin() as connection:
                driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
                await driver.execute(drift)
            try:
                with pytest.raises(RuntimeError, match="Unsafe runtime policy"):
                    await verify_runtime_database_security(engines[1], "application")
            finally:
                async with admin.begin() as connection:
                    driver = cast(
                        SQLDriver, (await connection.get_raw_connection()).driver_connection
                    )
                    await driver.execute("DROP POLICY IF EXISTS surprise_access ON vehicles")
                    for source in (
                        "tenant-bindings.sql",
                        "tenant-rls.sql",
                        "outbox-tenant-policy.sql",
                    ):
                        await driver.execute(Path("database", source).read_text(encoding="utf-8"))
        vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(), vin=VIN("ABC12345678901234"), tenant_id="grants-test"
        ).transition_to(VehicleStatus.ACTIVE)
        async with create_session_factory(admin)() as session:
            SQLAlchemyVehicleRepository(session).add(vehicle)
            await session.commit()
        issued = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key="grants-test",
        )
        store = SQLAlchemyOutboxStore(sessions["outbox_worker"])
        claimed = await store.claim_batch()
        assert len(claimed) == 1
        assert await store.schedule_retry(
            outbox_id=claimed[0].id,
            claim_token=claimed[0].claim_token,
            available_at=issued.command.created_at,
        )
        claimed = await store.claim_batch()
        assert await store.mark_published(
            outbox_id=claimed[0].id, claim_token=claimed[0].claim_token
        )
        publisher = AsyncMock()
        await RemoteCommandDispatchService(sessions["remote_command_worker"], publisher).dispatch(
            issued.command.id,
            expected=RequestedPayload.model_validate(
                create_remote_command_requested_event(issued.command).payload
            ),
        )
        publisher.publish.assert_awaited_once()
        device_service = DeviceDataService(sessions["app_user"])
        report = CommandReport(event_id=uuid4(), status="succeeded", occurred_at=datetime.now(UTC))
        assert (
            await device_service.report(
                tenant=vehicle.tenant_id,
                vehicle=str(vehicle.id),
                command_id=str(issued.command.id),
                report=report,
            )
            == "succeeded"
        )
        sample = TelemetrySample(
            event_id=uuid4(),
            measured_at=datetime.now(UTC),
            speed_kph=10,
            battery_percent=50,
            temperature_c=30,
        )
        assert await device_service.ingest(
            tenant=vehicle.tenant_id, vehicle=str(vehicle.id), sample=sample
        )
        assert not await device_service.ingest(
            tenant=vehicle.tenant_id, vehicle=str(vehicle.id), sample=sample
        )
        owner_sessions = create_session_factory(admin)
        # Replay only an unsent, unexpired valid command; audit and reset share one transaction.
        replayable = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.HONK,
            idempotency_key="operations-replay",
        )
        async with owner_sessions() as session, session.begin():
            item = await session.scalar(
                select(OutboxEventModel).where(
                    OutboxEventModel.event_id == f"remote-command:{replayable.command.id}:requested"
                )
            )
            assert item
            item.status, item.attempts, item.failure_code = "failed", 10, "retry_exhausted"
            item_id = item.id
        op_id = str(uuid4())
        options: dict[str, Any] = dict(
            outbox_id=item_id,
            operation_id=op_id,
            actor="incident-operator",
            reason="Recovered queue outage",
            expected_attempts=10,
        )
        assert (await replay_outbox(owner_sessions, **options))["dry_run"]
        async with owner_sessions() as session:
            assert await session.get(OperatorActionModel, op_id) is None
        assert not (await replay_outbox(owner_sessions, **options, apply=True))["dry_run"]
        assert (await replay_outbox(owner_sessions, **options, apply=True))["already_applied"]
        async with owner_sessions() as session, session.begin():
            item = await session.get(OutboxEventModel, item_id)
            assert item and item.status == "pending" and item.attempts == 0
            item.status, item.attempts = "failed", 10
            cmd = await session.get(RemoteCommandModel, str(replayable.command.id))
            assert cmd
            cmd.status = "succeeded"
        with pytest.raises(ValueError, match="terminal"):
            await replay_outbox(
                owner_sessions, **(options | {"operation_id": str(uuid4())}), apply=True
            )
        assert (await reconcile(owner_sessions))["outbox_status_counts"]
        overdue = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key="operations-timeout",
        )
        async with owner_sessions() as session, session.begin():
            cmd = await session.get(RemoteCommandModel, str(overdue.command.id))
            assert cmd
            cmd.status = "acknowledged"
            cmd.created_at = datetime.now(UTC) - timedelta(minutes=2)
            cmd.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        timeout_options: dict[str, Any] = {
            "actor": "incident-operator",
            "reason": "Execution ACK deadline exceeded",
        }
        assert (await timeout_commands(owner_sessions, **timeout_options))["count"] == 1
        assert (await timeout_commands(owner_sessions, **timeout_options, apply=True))["count"] == 1
        assert (await timeout_commands(owner_sessions, **timeout_options, apply=True))["count"] == 0
        async with owner_sessions() as session:
            cmd = await session.get(RemoteCommandModel, str(overdue.command.id))
            assert cmd and cmd.status == "timed_out"
            audit = await session.scalar(
                select(OperatorActionModel).where(
                    OperatorActionModel.target_id == str(overdue.command.id)
                )
            )
            assert audit and audit.evidence["previous_status"] == "acknowledged"
        client = Mock()
        client.get_queue_attributes.side_effect = lambda **kw: (
            {"Attributes": {"QueueArn": "arn:aws:sqs:ap-northeast-1:123456789012:dlq"}}
            if kw["QueueUrl"] == "dlq"
            else {
                "Attributes": {
                    "QueueArn": "arn:aws:sqs:ap-northeast-1:123456789012:source",
                    "RedrivePolicy": json.dumps(
                        {"deadLetterTargetArn": "arn:aws:sqs:ap-northeast-1:123456789012:dlq"}
                    ),
                }
            }
        )
        dlq_options: dict[str, Any] = dict(
            source_url="dlq",
            destination_url="source",
            operation_id=str(uuid4()),
            actor="incident-operator",
            reason="Reviewed all expired/poison messages",
        )
        assert (await redrive(owner_sessions, client, **dlq_options))["dry_run"]
        client.start_message_move_task.assert_not_called()
        with pytest.raises(ValueError, match="bulk"):
            await redrive(owner_sessions, client, **dlq_options, apply=True)
        client.start_message_move_task.side_effect = TimeoutError("Ambiguous transport failure")
        with pytest.raises(TimeoutError):
            await redrive(owner_sessions, client, **dlq_options, apply=True, allow_bulk=True)
        with pytest.raises(ValueError, match="Ambiguous"):
            await redrive(owner_sessions, client, **dlq_options, apply=True, allow_bulk=True)
        client.start_message_move_task.assert_called_once()
        confirmed_id = str(uuid4())
        client.start_message_move_task.side_effect = None
        client.start_message_move_task.return_value = {"TaskHandle": "confirmed-task"}
        started = await redrive(
            owner_sessions,
            client,
            **(dlq_options | {"operation_id": confirmed_id}),
            apply=True,
            allow_bulk=True,
        )
        assert started["state"] == "started"
        client.list_message_move_tasks.return_value = {
            "Results": [
                {
                    "TaskHandle": "confirmed-task",
                    "Status": "COMPLETED",
                    "ApproximateNumberOfMessagesMoved": 2,
                }
            ]
        }
        assert (await redrive_status(owner_sessions, client, operation_id=confirmed_id))[
            "Status"
        ] == "COMPLETED"
        async with owner_sessions() as session:
            action = await session.get(OperatorActionModel, confirmed_id)
            assert action and action.state == "complete"

        # A second publisher cannot overtake an earlier unfinished command.
        earlier_ordered = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key="ordered-first",
        )
        await RemoteCommandDispatchService(sessions["remote_command_worker"], AsyncMock()).dispatch(
            earlier_ordered.command.id,
            expected=RequestedPayload.model_validate(
                create_remote_command_requested_event(earlier_ordered.command).payload
            ),
        )
        second_ordered = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.UNLOCK,
            idempotency_key="ordered-next",
        )
        ordered_publisher = AsyncMock()
        ordered_service = RemoteCommandDispatchService(
            sessions["remote_command_worker"], ordered_publisher
        )
        with pytest.raises(RemoteCommandOrderPendingError):
            await ordered_service.dispatch(
                second_ordered.command.id,
                expected=RequestedPayload.model_validate(
                    create_remote_command_requested_event(second_ordered.command).payload
                ),
            )
        ordered_publisher.publish.assert_not_awaited()
        await device_service.report(
            tenant=vehicle.tenant_id,
            vehicle=str(vehicle.id),
            command_id=earlier_ordered.command.id.value,
            report=CommandReport(
                event_id=uuid4(), status="succeeded", occurred_at=datetime.now(UTC)
            ),
        )
        await ordered_service.dispatch(
            second_ordered.command.id,
            expected=RequestedPayload.model_validate(
                create_remote_command_requested_event(second_ordered.command).payload
            ),
        )
        ordered_publisher.publish.assert_awaited_once()
        # New role names do not bypass RLS even with direct SELECT grants.
        async with admin.begin() as connection:
            await connection.execute(
                text("CREATE ROLE future_runtime LOGIN PASSWORD 'ci-probe' NOSUPERUSER NOBYPASSRLS")
            )
            await connection.execute(text("GRANT CONNECT ON DATABASE postgres TO future_runtime"))
            await connection.execute(text("GRANT USAGE ON SCHEMA public TO future_runtime"))
            await connection.execute(
                text("GRANT SELECT ON vehicles,remote_commands,outbox_events TO future_runtime")
            )
        future_engine = create_database_engine(
            settings.model_copy(
                update={
                    "database_username": "future_runtime",
                    "database_password": SecretStr("ci-probe"),
                }
            )
        )
        engines.append(future_engine)
        async with future_engine.connect() as connection:
            for table in ("vehicles", "remote_commands", "outbox_events"):
                assert await connection.scalar(text(f"SELECT count(*) FROM {table}")) == 0
            await connection.execute(text("SELECT set_config('app.tenant_id','grants-test',true)"))
            assert await connection.scalar(text("SELECT count(*) FROM vehicles")) == 1

        # Real PostgreSQL RLS: two tenants, missing context, pooled reuse, raw SQL.
        foreign_vehicle = Vehicle.create(
            vehicle_id=VehicleId.new(), vin=VIN("XYZ12345678901234"), tenant_id="tenant-b"
        ).transition_to(VehicleStatus.ACTIVE)
        async with owner_sessions() as session:
            SQLAlchemyVehicleRepository(session).add(foreign_vehicle)
            await session.commit()
        foreign = await IssueRemoteCommandService(sessions["app_user"]).issue(
            vehicle_id=foreign_vehicle.id,
            tenant_id="tenant-b",
            command_type=RemoteCommandType.LOCK,
            idempotency_key="cross-tenant-test",
        )
        expected = RequestedPayload.model_validate(
            create_remote_command_requested_event(foreign.command).payload
        )
        rejecting_publisher = AsyncMock()
        dispatcher = RemoteCommandDispatchService(
            sessions["remote_command_worker"], rejecting_publisher
        )
        for change in (
            {"tenant_id": "grants-test"},
            {"vehicle_id": vehicle.id.value},
            {"command_type": "unlock"},
            {"created_at": expected.created_at + timedelta(seconds=1)},
            {"expires_at": expected.expires_at + timedelta(seconds=1)},
        ):
            forged = RequestedPayload.model_validate(expected.model_dump() | change)
            with pytest.raises((RemoteCommandDispatchCommandNotFoundError, InvalidMessageError)):
                await dispatcher.dispatch(foreign.command.id, expected=forged)
        rejecting_publisher.publish.assert_not_awaited()
        with pytest.raises(ResourceNotFoundError):
            await device_service.query(
                tenant="grants-test", vehicle=foreign_vehicle.id.value, limit=10
            )
        async with owner_sessions() as session:
            outbox_tenants = (
                await session.execute(
                    select(OutboxEventModel.tenant_id, OutboxEventModel.event_body)
                )
            ).all()
            assert {row.tenant_id for row in outbox_tenants} == {"grants-test", "tenant-b"}
            for row in outbox_tenants:
                assert row.tenant_id == json.loads(row.event_body)["payload"]["tenant_id"]
        async with sessions["app_user"]() as session:
            await set_tenant_scope(session, "grants-test")
            with pytest.raises(DBAPIError):
                await session.execute(
                    text("INSERT INTO outbox_events (tenant_id) VALUES ('tenant-b')")
                )
            await session.rollback()
        insert_event = text(
            "INSERT INTO outbox_events "
            "(id,event_id,event_type,destination,event_body,status,attempts,"
            "created_at,available_at) "
            "VALUES (:id,:id,'bad','vehicle-command',:body,'pending',0,now(),now())"
        )
        # Legacy poison payload remains inspectable without authorizing tenant API writes.
        poison_id = str(uuid4())
        async with owner_sessions() as session, session.begin():
            await session.execute(insert_event, {"id": poison_id, "body": "bad-json"})
            poison = await session.get(OutboxEventModel, poison_id)
            assert poison is not None and poison.tenant_id is None
            assert poison.event_body == "bad-json"
        for body in ("bad-json", json.dumps({"payload": {"tenant_id": "tenant-b"}})):
            async with sessions["app_user"]() as session:
                await set_tenant_scope(session, "grants-test")
                with pytest.raises(DBAPIError):
                    await session.execute(insert_event, {"id": str(uuid4()), "body": body})
                await session.rollback()
        for user in ("app_user", "remote_command_worker"):
            async with sessions[user]() as session:
                assert await session.scalar(text("SELECT count(*) FROM remote_commands")) == 0
                await set_tenant_scope(session, "grants-test")
                assert (
                    await session.scalar(
                        text("SELECT count(*) FROM remote_commands WHERE tenant_id='tenant-b'")
                    )
                    == 0
                )
                update_result = await session.execute(
                    text(
                        "UPDATE remote_commands SET status='failed' "
                        "WHERE tenant_id='tenant-b' RETURNING id"
                    )
                )
                assert update_result.all() == []
                backend = await session.scalar(text("SELECT pg_backend_pid()"))
                await session.commit()
                assert await session.scalar(text("SELECT pg_backend_pid()")) == backend
                assert await session.scalar(text("SELECT count(*) FROM remote_commands")) == 0
                await session.rollback()
                await set_tenant_scope(session, "tenant-b")
                assert await session.scalar(text("SELECT count(*) FROM remote_commands")) == 1
                await session.rollback()
                assert await session.scalar(text("SELECT count(*) FROM remote_commands")) == 0
        async with sessions["app_user"]() as session:
            await set_tenant_scope(session, "grants-test")
            session.add(
                TelemetrySampleModel(
                    event_id=str(uuid4()),
                    tenant_id="tenant-b",
                    vehicle_id=foreign_vehicle.id.value,
                    measured_at=datetime.now(UTC),
                    received_at=datetime.now(UTC),
                    sample={},
                )
            )
            with pytest.raises(DBAPIError):
                await session.commit()
            await session.rollback()
        async with owner_sessions() as session:
            command = await session.get(RemoteCommandModel, foreign.command.id.value)
            assert command is not None and command.status == "requested"
            policies = await session.scalar(
                text("SELECT count(*) FROM pg_policies WHERE policyname='tenant_guard'")
            )
            assert policies == 5

        # Even a stolen pinned login cannot select a foreign tenant by setting the GUC.
        async with admin.begin() as connection:
            await connection.execute(
                text("INSERT INTO runtime_tenant_bindings VALUES ('future_runtime','grants-test')")
            )
        async with future_engine.connect() as connection:
            await connection.execute(text("SELECT set_config('app.tenant_id','tenant-b',true)"))
            assert (
                await connection.scalar(
                    text("SELECT count(*) FROM vehicles WHERE tenant_id='tenant-b'")
                )
                == 0
            )
            assert (
                await connection.scalar(
                    text("SELECT count(*) FROM vehicles WHERE tenant_id='grants-test'")
                )
                == 1
            )
            with pytest.raises(DBAPIError):
                await connection.execute(
                    text("UPDATE runtime_tenant_bindings SET tenant_id='tenant-b'")
                )
            await connection.rollback()
        async with sessions["app_user"]() as session:
            assert not await session.scalar(
                text(
                    "SELECT has_column_privilege(current_user,"
                    "'remote_commands','dispatch_order','INSERT')"
                )
            )
        # All six real login roles: changing tenant GUC never changes ownership.
        for tenant, foreign_tenant in (("grants-test", "tenant-b"), ("tenant-b", "grants-test")):
            grants = Path("database/runtime-grants.sql").read_text(encoding="utf-8")
            for runtime, original in DATABASE_USERS.items():
                grants = grants.replace(original, runtime_database_user(runtime, tenant))
            async with admin.begin() as connection:
                driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
                await driver.execute(grants)
                for runtime in DATABASE_USERS:
                    username = runtime_database_user(runtime, tenant)
                    await connection.execute(
                        text("INSERT INTO runtime_tenant_bindings VALUES (:role,:tenant)"),
                        {"role": username, "tenant": tenant},
                    )
                    await driver.execute(f"ALTER ROLE {username} PASSWORD 'test-pinned'")
            for runtime in DATABASE_USERS:
                pinned = create_database_engine(
                    settings.model_copy(
                        update={
                            "database_username": runtime_database_user(runtime, tenant),
                            "database_password": SecretStr("test-pinned"),
                        }
                    )
                )
                engines.append(pinned)
                await verify_runtime_database_security(pinned, runtime, tenant_id=tenant)
                with pytest.raises(RuntimeError, match="Unsafe runtime database role"):
                    await verify_runtime_database_security(
                        pinned, runtime, tenant_id=foreign_tenant
                    )
                table = "outbox_events" if runtime == "outbox" else "remote_commands"
                async with pinned.connect() as connection:
                    await connection.execute(
                        text("SELECT set_config('app.tenant_id',:tenant,true)"),
                        {"tenant": foreign_tenant},
                    )
                    assert (
                        await connection.scalar(
                            text(f"SELECT count(*) FROM {table} WHERE tenant_id=:tenant"),
                            {"tenant": tenant},
                        )
                        > 0
                    )
                    assert (
                        await connection.scalar(
                            text(f"SELECT count(*) FROM {table} WHERE tenant_id=:tenant"),
                            {"tenant": foreign_tenant},
                        )
                        == 0
                    )
                    if runtime != "application":
                        updated = await connection.execute(
                            text(
                                f"UPDATE {table} SET status=status "
                                "WHERE tenant_id=:tenant RETURNING id"
                            ),
                            {"tenant": foreign_tenant},
                        )
                        assert updated.all() == []
                    await connection.rollback()
                    if runtime == "application":
                        with pytest.raises(DBAPIError):
                            await connection.execute(
                                insert_event,
                                {
                                    "id": str(uuid4()),
                                    "body": json.dumps({"payload": {"tenant_id": foreign_tenant}}),
                                },
                            )
                        await connection.rollback()
                    with pytest.raises(DBAPIError):
                        await connection.execute(
                            text("UPDATE runtime_tenant_bindings SET tenant_id=:tenant"),
                            {"tenant": foreign_tenant},
                        )
                    await connection.rollback()
                    with pytest.raises(DBAPIError):
                        await connection.execute(
                            text("CREATE TABLE public.pinned_forbidden (id int)")
                        )
                    await connection.rollback()
        denied = {
            "app_user": [
                "UPDATE remote_commands SET tenant_id = tenant_id",
                "DELETE FROM outbox_events",
            ],
            "outbox_worker": [
                "SELECT * FROM command_reports",
                "SELECT * FROM telemetry_samples",
                "SELECT * FROM vehicles",
                "SELECT * FROM remote_commands",
                "UPDATE outbox_events SET event_body = event_body",
                "DELETE FROM outbox_events",
            ],
            "remote_command_worker": [
                "SELECT * FROM command_reports",
                "SELECT * FROM telemetry_samples",
                "SELECT * FROM vehicles",
                "SELECT * FROM outbox_events",
                "UPDATE remote_commands SET tenant_id = tenant_id",
                "DELETE FROM remote_commands",
            ],
        }
        for user, statements in denied.items():
            for statement in [
                *statements,
                "SELECT * FROM operator_actions",
                "CREATE TABLE public.forbidden (id int)",
                "CREATE TEMP TABLE forbidden (id int)",
                "ALTER TABLE remote_commands ADD COLUMN forbidden int",
            ]:
                async with sessions[user]() as session:
                    with pytest.raises(DBAPIError):
                        await session.execute(text(statement))
                    await session.rollback()
        evidence(
            "12a-rls",
            {
                "dedicated_roles": 6,
                "cross_tenant_read": "denied",
                "cross_tenant_update": "zero rows",
                "foreign_insert": "denied",
                "binding_modification": "denied",
                "runtime_ddl": "denied",
                "policy_semantic_drift": "detected",
                "pooled_context_cleanup": "passed",
            },
        )
    finally:
        for engine in engines:
            await engine.dispose()
        subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
