from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    DatabaseRuntime,
    load_runtime_database_settings,
    migration_database_settings,
)


@pytest.mark.parametrize("runtime", list(DATABASE_USERS))
async def test_each_runtime_reads_only_its_secret(runtime: DatabaseRuntime) -> None:
    settings = Settings.model_construct()
    provider = AsyncMock()
    provider.get_secret.return_value = json.dumps(
        {
            "host": "db.internal",
            "port": 5432,
            "dbname": "vehicle",
            "username": DATABASE_USERS[runtime],
            "password": "isolated-password",
        }
    )
    resolved = await load_runtime_database_settings(settings, runtime, provider=provider)
    provider.get_secret.assert_awaited_once_with(f"/connected-vehicle/local/database/{runtime}")
    assert resolved.database_username == DATABASE_USERS[runtime]
    assert resolved.database_password.get_secret_value() == "isolated-password"
    assert settings.database_username != resolved.database_username


@pytest.mark.parametrize(
    "payload",
    [
        '{"password":"never-log-me"}',
        '{"host":"db","port":5432,"dbname":"db","username":"connected_vehicle",'
        '"password":"never-log-me"}',
        "invalid-never-log-me",
    ],
)
async def test_invalid_or_admin_secret_fails_closed_without_leaking(payload: str) -> None:
    provider = AsyncMock()
    provider.get_secret.return_value = payload
    with pytest.raises(ValueError) as error:
        await load_runtime_database_settings(
            Settings.model_construct(), "outbox", provider=provider
        )
    assert "never-log-me" not in str(error.value)


async def test_backend_failure_does_not_fall_back() -> None:
    provider = AsyncMock()
    provider.get_secret.side_effect = RuntimeError("access denied")
    with pytest.raises(RuntimeError, match="access denied"):
        await load_runtime_database_settings(
            Settings.model_construct(), "outbox", provider=provider
        )


def test_migrations_require_independent_credentials() -> None:
    with pytest.raises(ValueError, match="independent"):
        migration_database_settings(Settings.model_construct())
    with pytest.raises(ValueError, match="independent"):
        migration_database_settings(
            Settings.model_construct(
                migration_database_username="outbox_worker",
                migration_database_password=SecretStr("bad"),
            )
        )
    result = migration_database_settings(
        Settings.model_construct(
            migration_database_username="migration_admin",
            migration_database_password=SecretStr("admin-secret"),
        )
    )
    assert result.database_username == "migration_admin"
