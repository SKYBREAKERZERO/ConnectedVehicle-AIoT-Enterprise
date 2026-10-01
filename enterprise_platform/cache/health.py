from __future__ import annotations

import asyncio
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError


@dataclass(frozen=True, slots=True)
class RedisHealthResult:
    healthy: bool
    status: str


async def check_redis_health(
    client: Redis,
    *,
    timeout_seconds: float,
) -> RedisHealthResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            response = await client.ping()

        if response is not True:
            return RedisHealthResult(
                healthy=False,
                status="unexpected_response",
            )

        return RedisHealthResult(
            healthy=True,
            status="ok",
        )

    except TimeoutError:
        return RedisHealthResult(
            healthy=False,
            status="timeout",
        )

    except RedisError:
        return RedisHealthResult(
            healthy=False,
            status="redis_error",
        )
