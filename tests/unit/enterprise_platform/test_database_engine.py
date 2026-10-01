from __future__ import annotations

from unittest.mock import Mock, patch

from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import (
    build_database_url,
    create_database_engine,
)


def test_build_database_url_uses_asyncpg() -> None:
    settings = Settings(
        database_host="db.internal",
        database_port=5433,
        database_name="vehicle_platform",
        database_username="platform_user",
        database_password="p@ss:word",
        _env_file=None,
    )

    url = build_database_url(settings)

    assert url.drivername == "postgresql+asyncpg"
    assert url.username == "platform_user"
    assert url.password == "p@ss:word"
    assert url.host == "db.internal"
    assert url.port == 5433
    assert url.database == "vehicle_platform"


def test_create_database_engine_applies_pool_policy() -> None:
    settings = Settings(
        database_pool_size=12,
        database_max_overflow=24,
        database_pool_timeout_seconds=15.0,
        database_connect_timeout_seconds=4.0,
        _env_file=None,
    )

    expected_engine = Mock(spec=AsyncEngine)

    with patch(
        "enterprise_platform.database.engine.create_async_engine",
        return_value=expected_engine,
    ) as create_engine:
        engine = create_database_engine(settings)

    assert engine is expected_engine

    create_engine.assert_called_once()

    args, kwargs = create_engine.call_args

    assert len(args) == 1
    assert args[0].drivername == "postgresql+asyncpg"

    assert kwargs["pool_pre_ping"] is True
    assert kwargs["pool_size"] == 12
    assert kwargs["max_overflow"] == 24
    assert kwargs["pool_timeout"] == 15.0
    assert kwargs["connect_args"] == {"timeout": 4.0}
