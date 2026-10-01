from __future__ import annotations

from enterprise_platform.cache.client import RedisResources


async def close_redis_resources(resources: RedisResources) -> None:
    await resources.client.aclose(close_connection_pool=False)
    await resources.pool.aclose()
