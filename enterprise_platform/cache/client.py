from __future__ import annotations

from dataclasses import dataclass

from pydantic import SecretStr
from redis.asyncio import ConnectionPool, Redis

from enterprise_platform.config.settings import Settings


@dataclass(frozen=True, slots=True)
class RedisResources:
    client: Redis
    pool: ConnectionPool


@dataclass(frozen=True, slots=True)
class CacheKeyBuilder:
    prefix: str

    def __post_init__(self) -> None:
        normalized = self.prefix.strip().strip(":")

        if not normalized:
            raise ValueError("Redis key prefix must not be empty.")

        object.__setattr__(self, "prefix", normalized)

    def build(self, *parts: str) -> str:
        normalized_parts = [part.strip().strip(":") for part in parts if part.strip().strip(":")]

        if not normalized_parts:
            raise ValueError("At least one Redis key component is required.")

        return ":".join((self.prefix, *normalized_parts))


def _secret_value_or_none(value: SecretStr | None) -> str | None:
    if value is None:
        return None

    secret = value.get_secret_value().strip()

    return secret or None


def create_redis_resources(settings: Settings) -> RedisResources:
    pool = ConnectionPool(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        username=settings.redis_username or None,
        password=_secret_value_or_none(settings.redis_password),
        socket_connect_timeout=settings.redis_connect_timeout_seconds,
        socket_timeout=settings.redis_socket_timeout_seconds,
        max_connections=settings.redis_max_connections,
        decode_responses=True,
        encoding="utf-8",
    )

    client = Redis(
        connection_pool=pool,
    )

    return RedisResources(
        client=client,
        pool=pool,
    )


def create_cache_key_builder(settings: Settings) -> CacheKeyBuilder:
    return CacheKeyBuilder(
        prefix=settings.redis_key_prefix,
    )
