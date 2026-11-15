from __future__ import annotations

import pytest
from pydantic import SecretStr
from redis.asyncio.connection import SSLConnection

from enterprise_platform.cache.client import (
    CacheKeyBuilder,
    create_redis_resources,
)
from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
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


def test_aws_staging_redis_verifies_tls_certificate_and_hostname() -> None:
    settings = Settings(
        app_env=AppEnvironment.STAGING,
        cloud_runtime=CloudRuntime.AWS,
        redis_tls_enabled=True,
        redis_password=SecretStr("test-token"),
    )
    pool = create_redis_resources(settings).pool
    assert pool.connection_class is SSLConnection
    assert pool.connection_kwargs["ssl_cert_reqs"] == "required"
    assert pool.connection_kwargs["ssl_check_hostname"] is True


@pytest.mark.parametrize(("tls", "password"), [(False, "token"), (True, ""), (True, " ")])
def test_aws_staging_redis_refuses_missing_tls_or_auth(tls: bool, password: str) -> None:
    settings = Settings(
        app_env=AppEnvironment.STAGING,
        cloud_runtime=CloudRuntime.AWS,
        redis_tls_enabled=tls,
        redis_password=SecretStr(password),
    )
    with pytest.raises(ValueError, match="requires TLS and authentication"):
        create_redis_resources(settings)
