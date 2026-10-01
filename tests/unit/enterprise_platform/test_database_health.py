from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.database.health import (
    DatabaseHealthFailure,
    check_database_health,
)


async def test_database_health_returns_healthy_for_successful_probe() -> None:
    engine = Mock(spec=AsyncEngine)
    connection = AsyncMock()

    connection_context = MagicMock()
    connection_context.__aenter__ = AsyncMock(return_value=connection)
    connection_context.__aexit__ = AsyncMock(return_value=False)

    engine.connect.return_value = connection_context

    result = await check_database_health(
        engine,
        timeout_seconds=1.0,
    )

    assert result.healthy is True
    assert result.failure is None

    connection.execute.assert_awaited_once()

    statement = connection.execute.await_args.args[0]
    assert str(statement) == "SELECT 1"


async def test_database_health_returns_database_error() -> None:
    engine = Mock(spec=AsyncEngine)
    engine.connect.side_effect = SQLAlchemyError("database unavailable")

    result = await check_database_health(
        engine,
        timeout_seconds=1.0,
    )

    assert result.healthy is False
    assert result.failure is DatabaseHealthFailure.DATABASE_ERROR


async def test_database_health_returns_timeout() -> None:
    engine = Mock(spec=AsyncEngine)
    connection = AsyncMock()

    async def delayed_enter() -> object:
        await asyncio.sleep(0.05)
        return connection

    connection_context = MagicMock()
    connection_context.__aenter__ = AsyncMock(side_effect=delayed_enter)
    connection_context.__aexit__ = AsyncMock(return_value=False)

    engine.connect.return_value = connection_context

    result = await check_database_health(
        engine,
        timeout_seconds=0.001,
    )

    assert result.healthy is False
    assert result.failure is DatabaseHealthFailure.TIMEOUT
