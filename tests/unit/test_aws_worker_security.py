"""AWS worker transport and Redis TLS regression/security contracts."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from redis.asyncio.connection import SSLConnection

from connected_vehicle.remote_command.aws_iot_publisher import (
    IoTCoreMQTTAdapter,
    create_aws_iot_publisher,
)
from enterprise_platform.cache.client import create_redis_resources
from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings


def test_aws_redis_connections_require_cert_verified_tls() -> None:
    settings = Settings.model_construct(
        cloud_runtime=CloudRuntime.AWS,
        redis_host="redis.internal",
        redis_port=6379,
        redis_db=0,
        redis_username=None,
        redis_password=None,
        redis_connect_timeout_seconds=3,
        redis_socket_timeout_seconds=5,
        redis_max_connections=20,
        redis_key_prefix="staging",
    )
    with (
        patch("enterprise_platform.cache.client.ConnectionPool") as pool,
        patch("enterprise_platform.cache.client.Redis"),
    ):
        create_redis_resources(settings)
    options = pool.call_args.kwargs
    assert options["connection_class"] is SSLConnection
    assert options["ssl_cert_reqs"] == "required"


def test_localstack_redis_does_not_force_cloud_tls() -> None:
    settings = Settings.model_construct(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        redis_host="localhost",
        redis_port=16379,
        redis_db=0,
        redis_username=None,
        redis_password=None,
        redis_connect_timeout_seconds=3,
        redis_socket_timeout_seconds=5,
        redis_max_connections=20,
        redis_key_prefix="local",
    )
    with (
        patch("enterprise_platform.cache.client.ConnectionPool") as pool,
        patch("enterprise_platform.cache.client.Redis"),
    ):
        create_redis_resources(settings)
    assert "connection_class" not in pool.call_args.kwargs


@pytest.mark.asyncio
async def test_iot_core_adapter_enforces_tenant_topic_qos_and_no_retention() -> None:
    service = Mock()
    adapter = IoTCoreMQTTAdapter(service, "staging_tenant_01")
    topic = "tenants/staging_tenant_01/vehicles/vehicle-1/commands"
    await adapter.publish(topic, b'{"id":"test"}', qos=1, retain=False)
    service.publish.assert_called_once_with(
        topic=topic, payload=b'{"id":"test"}', qos=1, retain=False
    )
    for bad_topic in (
        "tenants/foreign/vehicles/vehicle-1/commands",
        "tenants/staging_tenant_01/vehicles/+/commands",
        "tenants/staging_tenant_01/vehicles/vehicle-1/telemetry",
    ):
        with pytest.raises(ValueError, match="Invalid tenant"):
            await adapter.publish(bad_topic, b"x", qos=1, retain=False)
    with pytest.raises(ValueError, match="Invalid tenant"):
        await adapter.publish(topic, b"x", qos=0, retain=False)
    with pytest.raises(ValueError, match="Invalid tenant"):
        await adapter.publish(topic, b"x", qos=1, retain=True)


def test_iot_core_requires_aws_staging_endpoint_and_pinned_tenant() -> None:
    good = Settings.model_construct(
        cloud_runtime=CloudRuntime.AWS,
        app_env=AppEnvironment.STAGING,
        aws_region="ap-northeast-1",
        aws_endpoint_url=None,
        aws_iot_data_endpoint="abc123-ats.iot.ap-northeast-1.amazonaws.com",
        database_tenant_id="staging_tenant_01",
        aws_connect_timeout_seconds=3.0,
        aws_read_timeout_seconds=10.0,
    )
    with patch("connected_vehicle.remote_command.aws_iot_publisher.boto3.client") as aws:
        result = create_aws_iot_publisher(good)
    assert result is not None
    assert aws.call_args.args == ("iot-data",)
    assert aws.call_args.kwargs["endpoint_url"].startswith("https://")
    for changes in (
        {"aws_endpoint_url": "http://localhost:4566"},
        {"database_tenant_id": "tenant/#"},
        {"aws_iot_data_endpoint": "evil.example.com"},
        {"cloud_runtime": CloudRuntime.LOCALSTACK},
    ):
        with pytest.raises(ValueError):
            create_aws_iot_publisher(good.model_copy(update=changes))
