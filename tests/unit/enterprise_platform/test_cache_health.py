from __future__ import annotations

import asyncio
from typing import cast
from unittest.mock import AsyncMock

from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from enterprise_platform.cache.health import check_redis_health


async def test_redis_health_returns_healthy_for_successful_ping() -> None:
    client = cast(Redis, AsyncMock())
    cast(AsyncMock, client).ping = AsyncMock(return_value=True)

    result = await check_redis_health(
        client,
        timeout_seconds=1.0,
    )

    assert result.healthy is True
    assert result.status == "ok"


async def test_redis_health_returns_redis_error() -> None:
    client = cast(Redis, AsyncMock())
    cast(AsyncMock, client).ping = AsyncMock(side_effect=ConnectionError("Redis unavailable"))

    result = await check_redis_health(
        client,
        timeout_seconds=1.0,
    )

    assert result.healthy is False
    assert result.status == "redis_error"


async def test_redis_health_returns_timeout() -> None:
    async def slow_ping() -> bool:
        await asyncio.sleep(1)
        return True

    client = cast(Redis, AsyncMock())
    cast(AsyncMock, client).ping = AsyncMock(side_effect=slow_ping)

    result = await check_redis_health(
        client,
        timeout_seconds=0.001,
    )

    assert result.healthy is False
    assert result.status == "timeout"
