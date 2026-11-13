from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict

from pydantic import SecretStr
from redis.asyncio import ConnectionPool, Redis
from redis.asyncio.connection import Connection, SSLConnection

from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings


class RedisTLSOptions(TypedDict, total=False):
    ssl_cert_reqs: str
    ssl_check_hostname: bool


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
    password = _secret_value_or_none(settings.redis_password)
    if (
        settings.app_env == AppEnvironment.STAGING
        and settings.cloud_runtime == CloudRuntime.AWS
        and (not settings.redis_tls_enabled or not password)
    ):
        raise ValueError("AWS Staging Redis requires TLS and authentication")
    tls: RedisTLSOptions = (
        {"ssl_cert_reqs": "required", "ssl_check_hostname": True}
        if settings.redis_tls_enabled
        else {}
    )
    pool = ConnectionPool(
        connection_class=SSLConnection if settings.redis_tls_enabled else Connection,
        **tls,
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        username=settings.redis_username or None,
        password=password,
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
