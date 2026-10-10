from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock

from redis.asyncio import ConnectionPool, Redis

from enterprise_platform.cache.client import RedisResources
from enterprise_platform.cache.lifecycle import close_redis_resources


async def test_close_redis_resources_closes_client_and_pool() -> None:
    client = cast(Redis, AsyncMock())
    pool = cast(ConnectionPool, AsyncMock())

    cast(AsyncMock, client).aclose = AsyncMock()
    cast(AsyncMock, pool).aclose = AsyncMock()

    resources = RedisResources(
        client=client,
        pool=pool,
    )

    await close_redis_resources(resources)

    cast(AsyncMock, client.aclose).assert_awaited_once_with(close_connection_pool=False)
    cast(AsyncMock, pool.aclose).assert_awaited_once_with()
