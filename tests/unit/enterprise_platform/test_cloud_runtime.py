from enterprise_platform.cloud.runtime import resolve_cloud_runtime
from enterprise_platform.config.environment import CloudRuntime
from tests.settings_helpers import isolated_settings


def test_localstack_runtime_uses_configured_endpoint() -> None:
    settings = isolated_settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_region="ap-northeast-1",
        aws_endpoint_url="http://localstack:4566",
        _env_file=None,
    )

    runtime = resolve_cloud_runtime(settings)

    assert runtime.runtime is CloudRuntime.LOCALSTACK
    assert runtime.region == "ap-northeast-1"
    assert runtime.endpoint_url == "http://localstack:4566"
    assert runtime.is_local is True
    assert runtime.is_aws is False


def test_localstack_runtime_uses_safe_default_endpoint() -> None:
    settings = isolated_settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_endpoint_url=None,
        _env_file=None,
    )

    runtime = resolve_cloud_runtime(settings)

    assert runtime.endpoint_url == "http://localhost:4566"


def test_aws_runtime_does_not_use_localstack_endpoint() -> None:
    settings = isolated_settings(
        cloud_runtime=CloudRuntime.AWS,
        aws_region="ap-northeast-1",
        aws_endpoint_url="http://localhost:4566",
        _env_file=None,
    )

    runtime = resolve_cloud_runtime(settings)

    assert runtime.runtime is CloudRuntime.AWS
    assert runtime.region == "ap-northeast-1"
    assert runtime.endpoint_url is None
    assert runtime.is_local is False
    assert runtime.is_aws is True
