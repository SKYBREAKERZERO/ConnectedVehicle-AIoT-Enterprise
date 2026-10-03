from __future__ import annotations

from typing import Protocol, cast
from uuid import uuid4

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.security.factory import (
    create_aws_secrets_manager_provider,
)


class SecretsManagerIntegrationClient(Protocol):
    def create_secret(
        self,
        *,
        Name: str,
        SecretString: str,
    ) -> object: ...

    def put_secret_value(
        self,
        *,
        SecretId: str,
        SecretString: str,
    ) -> object: ...

    def delete_secret(
        self,
        *,
        SecretId: str,
        ForceDeleteWithoutRecovery: bool,
    ) -> object: ...


@pytest.mark.asyncio
async def test_localstack_secrets_manager_round_trip() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK

    secret_name = f"connected-vehicle/integration/{uuid4()}"

    initial_value = "integration-secret-v1"
    updated_value = "integration-secret-v2"

    client = cast(
        SecretsManagerIntegrationClient,
        AWSClientFactory(settings).secrets_manager(),
    )

    provider = create_aws_secrets_manager_provider(settings)

    try:
        client.create_secret(
            Name=secret_name,
            SecretString=initial_value,
        )

        assert await provider.get_secret(secret_name) == initial_value

        client.put_secret_value(
            SecretId=secret_name,
            SecretString=updated_value,
        )

        assert await provider.get_secret(secret_name) == updated_value

    finally:
        client.delete_secret(
            SecretId=secret_name,
            ForceDeleteWithoutRecovery=True,
        )
