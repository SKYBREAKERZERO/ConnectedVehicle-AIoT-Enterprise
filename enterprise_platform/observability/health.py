from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.cache.health import check_redis_health
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.health import check_database_health


class ReadinessStatus(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"


@dataclass(frozen=True, slots=True)
class DependencyHealth:
    healthy: bool
    status: str


@dataclass(frozen=True, slots=True)
class ReadinessResult:
    status: ReadinessStatus
    database: DependencyHealth
    redis: DependencyHealth

    @property
    def ready(self) -> bool:
        return self.status is ReadinessStatus.READY


async def check_readiness(
    *,
    engine: AsyncEngine,
    redis_client: Redis,
    settings: Settings,
) -> ReadinessResult:
    database_result, redis_result = await asyncio.gather(
        check_database_health(
            engine,
            settings.database_health_timeout_seconds,
        ),
        check_redis_health(
            redis_client,
            timeout_seconds=settings.redis_health_timeout_seconds,
        ),
    )

    database_status = "ok"

    if not database_result.healthy:
        database_status = (
            database_result.failure.value if database_result.failure is not None else "unknown"
        )

    database_health = DependencyHealth(
        healthy=database_result.healthy,
        status=database_status,
    )

    redis_health = DependencyHealth(
        healthy=redis_result.healthy,
        status=redis_result.status,
    )

    readiness_status = (
        ReadinessStatus.READY
        if database_health.healthy and redis_health.healthy
        else ReadinessStatus.NOT_READY
    )

    return ReadinessResult(
        status=readiness_status,
        database=database_health,
        redis=redis_health,
    )
