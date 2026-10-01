from __future__ import annotations

import pytest
from pydantic import SecretStr

from enterprise_platform.cache.client import (
    CacheKeyBuilder,
    create_redis_resources,
)
from enterprise_platform.config.settings import Settings


def test_create_redis_resources_applies_connection_policy() -> None:
    settings = Settings(
        redis_host="redis.example.internal",
        redis_port=6380,
        redis_db=2,
        redis_username="service-user",
        redis_password=SecretStr("secret-password"),
        redis_connect_timeout_seconds=4.0,
        redis_socket_timeout_seconds=7.0,
        redis_max_connections=75,
    )

    resources = create_redis_resources(settings)
    kwargs = resources.pool.connection_kwargs

    assert kwargs["host"] == "redis.example.internal"
    assert kwargs["port"] == 6380
    assert kwargs["db"] == 2
    assert kwargs["username"] == "service-user"
    assert kwargs["password"] == "secret-password"
    assert kwargs["socket_connect_timeout"] == 4.0
    assert kwargs["socket_timeout"] == 7.0
    assert resources.pool.max_connections == 75
    assert kwargs["decode_responses"] is True
    assert resources.client.connection_pool is resources.pool


def test_cache_key_builder_creates_namespaced_key() -> None:
    builder = CacheKeyBuilder(prefix="connected-vehicle")

    assert builder.build("vehicle", "VIN001") == "connected-vehicle:vehicle:VIN001"


def test_cache_key_builder_normalizes_colons() -> None:
    builder = CacheKeyBuilder(prefix=":connected-vehicle:")

    assert builder.build(":command:", ":CMD001:") == "connected-vehicle:command:CMD001"


def test_cache_key_builder_rejects_empty_key() -> None:
    builder = CacheKeyBuilder(prefix="connected-vehicle")

    with pytest.raises(
        ValueError,
        match="At least one Redis key component",
    ):
        builder.build("")
