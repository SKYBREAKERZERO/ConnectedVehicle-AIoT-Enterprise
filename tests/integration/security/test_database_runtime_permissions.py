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

from connected_vehicle.device_data import CommandReport, TelemetrySample
from connected_vehicle.device_service import DeviceDataService
from connected_vehicle.remote_command.dispatch_service import RemoteCommandDispatchService
from connected_vehicle.remote_command.domain import RemoteCommandType
from connected_vehicle.remote_command.persistence.models import RemoteCommandModel
from connected_vehicle.remote_command.service import IssueRemoteCommandService
from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from connected_vehicle.vehicle.persistence.repository import SQLAlchemyVehicleRepository
from database.dlq_operations import redrive
from database.operations import reconcile, replay_outbox, timeout_commands
from database.provision_runtime_credentials import SQLDriver, provision
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.base import Base
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.operations import OperatorActionModel
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.session import create_session_factory


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
            sessions[user] = create_session_factory(engine)
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
            issued.command.id
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
    finally:
        for engine in engines:
            await engine.dispose()
        subprocess.run(["docker", "rm", "-f", name], check=True, capture_output=True)
