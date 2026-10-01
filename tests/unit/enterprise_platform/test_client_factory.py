from __future__ import annotations

from unittest.mock import Mock, patch

from botocore.client import BaseClient
from botocore.config import Config

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings


def test_localstack_client_receives_endpoint_url() -> None:
    settings = Settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_region="ap-northeast-1",
        aws_endpoint_url="http://localstack:4566",
        _env_file=None,
    )

    expected_client = Mock(spec=BaseClient)

    with patch(
        "enterprise_platform.cloud.client_factory.boto3.client",
        return_value=expected_client,
    ) as boto_client:
        factory = AWSClientFactory(settings)
        client = factory.sqs()

    assert client is expected_client

    boto_client.assert_called_once()

    args, kwargs = boto_client.call_args

    assert args == ("sqs",)
    assert kwargs["region_name"] == "ap-northeast-1"
    assert kwargs["endpoint_url"] == "http://localstack:4566"
    assert isinstance(kwargs["config"], Config)


def test_aws_client_does_not_receive_endpoint_override() -> None:
    settings = Settings(
        cloud_runtime=CloudRuntime.AWS,
        aws_region="ap-northeast-1",
        aws_endpoint_url="http://localhost:4566",
        _env_file=None,
    )

    expected_client = Mock(spec=BaseClient)

    with patch(
        "enterprise_platform.cloud.client_factory.boto3.client",
        return_value=expected_client,
    ) as boto_client:
        factory = AWSClientFactory(settings)
        client = factory.s3()

    assert client is expected_client

    boto_client.assert_called_once()

    args, kwargs = boto_client.call_args

    assert args == ("s3",)
    assert kwargs["region_name"] == "ap-northeast-1"
    assert "endpoint_url" not in kwargs
    assert isinstance(kwargs["config"], Config)


def test_client_factory_configures_timeouts_and_retries() -> None:
    settings = Settings(
        aws_connect_timeout_seconds=4.0,
        aws_read_timeout_seconds=12.0,
        aws_max_attempts=5,
        _env_file=None,
    )

    expected_client = Mock(spec=BaseClient)

    with patch(
        "enterprise_platform.cloud.client_factory.boto3.client",
        return_value=expected_client,
    ) as boto_client:
        factory = AWSClientFactory(settings)
        factory.sqs()

    _, kwargs = boto_client.call_args
    sdk_config = kwargs["config"]

    assert isinstance(sdk_config, Config)
    assert sdk_config.connect_timeout == 4.0
    assert sdk_config.read_timeout == 12.0
    assert sdk_config.retries["total_max_attempts"] == 5
    assert sdk_config.retries["mode"] == "standard"
