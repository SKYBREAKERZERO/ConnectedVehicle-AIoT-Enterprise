from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle import device_data as _device_data  # noqa: F401
from connected_vehicle.remote_command.dispatch_service import RemoteCommandDispatchService
from connected_vehicle.remote_command.domain import RemoteCommandType
from connected_vehicle.remote_command.service import IssueRemoteCommandService
from connected_vehicle.vehicle import VIN, Vehicle, VehicleId, VehicleStatus
from connected_vehicle.vehicle.persistence.repository import SQLAlchemyVehicleRepository
from database.provision_runtime_credentials import SQLDriver, provision
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.base import Base
from enterprise_platform.database.engine import create_database_engine
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
        denied = {
            "app_user": [
                "UPDATE remote_commands SET tenant_id = tenant_id",
                "DELETE FROM outbox_events",
            ],
            "outbox_worker": [
                "SELECT * FROM vehicles",
                "SELECT * FROM remote_commands",
                "UPDATE outbox_events SET event_body = event_body",
                "DELETE FROM outbox_events",
            ],
            "remote_command_worker": [
                "SELECT * FROM vehicles",
                "SELECT * FROM outbox_events",
                "UPDATE remote_commands SET tenant_id = tenant_id",
                "DELETE FROM remote_commands",
            ],
        }
        for user, statements in denied.items():
            for statement in [
                *statements,
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
