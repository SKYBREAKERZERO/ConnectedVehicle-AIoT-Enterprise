from unittest.mock import patch

import pytest

from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings
from scripts.verify_tenant_local import verify, verify_matrix


@pytest.mark.parametrize(
    "runtime,endpoint",
    [
        (CloudRuntime.AWS, "http://127.0.0.1:14566"),
        (CloudRuntime.LOCALSTACK, "https://secretsmanager.ap-northeast-1.amazonaws.com"),
    ],
)
async def test_local_verifier_rejects_real_aws_before_creating_client(
    runtime: CloudRuntime,
    endpoint: str,
) -> None:
    settings = Settings.model_construct(cloud_runtime=runtime, aws_endpoint_url=endpoint)
    with patch("scripts.verify_tenant_local.boto3.client") as client:
        with pytest.raises(ValueError, match="loopback LocalStack"):
            await verify({"scope": "localstack-only"}, settings)
        client.assert_not_called()


async def test_matrix_requires_two_distinct_tenants_before_client_creation() -> None:
    with patch("scripts.verify_tenant_local.boto3.client") as client:
        with pytest.raises(ValueError, match="distinct tenants"):
            await verify_matrix([], Settings.model_construct())
        client.assert_not_called()
