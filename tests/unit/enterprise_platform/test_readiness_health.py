from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

import enterprise_platform.observability.health as health_module
from enterprise_platform.cache.health import RedisHealthResult
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.health import (
    DatabaseHealthFailure,
    DatabaseHealthResult,
)
from enterprise_platform.observability.health import (
    ReadinessStatus,
    check_readiness,
)


async def test_readiness_is_ready_when_all_dependencies_are_healthy(
    monkeypatch,
) -> None:
    database_probe = AsyncMock(return_value=DatabaseHealthResult(healthy=True))
    redis_probe = AsyncMock(
        return_value=RedisHealthResult(
            healthy=True,
            status="ok",
        )
    )

    monkeypatch.setattr(
        health_module,
        "check_database_health",
        database_probe,
    )
    monkeypatch.setattr(
        health_module,
        "check_redis_health",
        redis_probe,
    )

    result = await check_readiness(
        engine=cast(AsyncEngine, object()),
        redis_client=cast(Redis, object()),
        settings=Settings(),
    )

    assert result.ready is True
    assert result.status is ReadinessStatus.READY

    assert result.database.healthy is True
    assert result.database.status == "ok"

    assert result.redis.healthy is True
    assert result.redis.status == "ok"


async def test_readiness_is_not_ready_when_database_is_unhealthy(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        health_module,
        "check_database_health",
        AsyncMock(
            return_value=DatabaseHealthResult(
                healthy=False,
                failure=DatabaseHealthFailure.TIMEOUT,
            )
        ),
    )

    monkeypatch.setattr(
        health_module,
        "check_redis_health",
        AsyncMock(
            return_value=RedisHealthResult(
                healthy=True,
                status="ok",
            )
        ),
    )

    result = await check_readiness(
        engine=cast(AsyncEngine, object()),
        redis_client=cast(Redis, object()),
        settings=Settings(),
    )

    assert result.ready is False
    assert result.status is ReadinessStatus.NOT_READY
    assert result.database.status == "timeout"
    assert result.redis.status == "ok"


async def test_readiness_is_not_ready_when_redis_is_unhealthy(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        health_module,
        "check_database_health",
        AsyncMock(
            return_value=DatabaseHealthResult(
                healthy=True,
            )
        ),
    )

    monkeypatch.setattr(
        health_module,
        "check_redis_health",
        AsyncMock(
            return_value=RedisHealthResult(
                healthy=False,
                status="redis_error",
            )
        ),
    )

    result = await check_readiness(
        engine=cast(AsyncEngine, object()),
        redis_client=cast(Redis, object()),
        settings=Settings(),
    )

    assert result.ready is False
    assert result.status is ReadinessStatus.NOT_READY
    assert result.database.status == "ok"
    assert result.redis.status == "redis_error"
