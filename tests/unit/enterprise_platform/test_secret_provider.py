from __future__ import annotations

from typing import cast

import pytest
from botocore.exceptions import ClientError

from enterprise_platform.security.secrets import (
    AWSSecretsManagerSecretProvider,
    EnvironmentSecretProvider,
    SecretAccessError,
    SecretNotFoundError,
    SecretValueFormatError,
    SecretValueResponse,
)


class FakeSecretsManagerClient:
    def __init__(
        self,
        response: SecretValueResponse,
    ) -> None:
        self._response = response
        self.requested_secret_id: str | None = None

    def get_secret_value(
        self,
        *,
        SecretId: str,
    ) -> SecretValueResponse:
        self.requested_secret_id = SecretId
        return self._response


class FailingSecretsManagerClient:
    def __init__(
        self,
        error_code: str,
    ) -> None:
        self._error_code = error_code

    def get_secret_value(
        self,
        *,
        SecretId: str,
    ) -> SecretValueResponse:
        del SecretId

        raise ClientError(
            {
                "Error": {
                    "Code": self._error_code,
                    "Message": "backend failure",
                }
            },
            "GetSecretValue",
        )


@pytest.mark.asyncio
async def test_environment_provider_returns_secret() -> None:
    provider = EnvironmentSecretProvider(
        {
            "DATABASE_PASSWORD": "super-secret",
        }
    )

    value = await provider.get_secret(" DATABASE_PASSWORD ")

    assert value == "super-secret"


@pytest.mark.asyncio
async def test_environment_provider_rejects_missing_secret() -> None:
    provider = EnvironmentSecretProvider({})

    with pytest.raises(SecretNotFoundError):
        await provider.get_secret("DATABASE_PASSWORD")


@pytest.mark.asyncio
async def test_environment_provider_rejects_empty_value() -> None:
    provider = EnvironmentSecretProvider(
        {
            "DATABASE_PASSWORD": "",
        }
    )

    with pytest.raises(SecretValueFormatError):
        await provider.get_secret("DATABASE_PASSWORD")


@pytest.mark.asyncio
async def test_aws_provider_returns_secret_string() -> None:
    client = FakeSecretsManagerClient(
        {
            "SecretString": "aws-secret",
        }
    )

    provider = AWSSecretsManagerSecretProvider(client)

    value = await provider.get_secret(" connected-vehicle/database ")

    assert value == "aws-secret"
    assert client.requested_secret_id == "connected-vehicle/database"


@pytest.mark.asyncio
async def test_aws_provider_decodes_binary_secret() -> None:
    client = FakeSecretsManagerClient(
        {
            "SecretBinary": b"binary-secret",
        }
    )

    provider = AWSSecretsManagerSecretProvider(client)

    value = await provider.get_secret("connected-vehicle/binary")

    assert value == "binary-secret"


@pytest.mark.asyncio
async def test_aws_provider_maps_resource_not_found() -> None:
    client = FailingSecretsManagerClient("ResourceNotFoundException")

    provider = AWSSecretsManagerSecretProvider(client)

    with pytest.raises(SecretNotFoundError):
        await provider.get_secret("missing-secret")


@pytest.mark.asyncio
async def test_aws_provider_maps_backend_failure_without_secret_value() -> None:
    client = FailingSecretsManagerClient("AccessDeniedException")

    provider = AWSSecretsManagerSecretProvider(client)

    with pytest.raises(SecretAccessError) as exc_info:
        await provider.get_secret("protected-secret")

    assert "backend failure" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_aws_provider_rejects_unsupported_response() -> None:
    client = FakeSecretsManagerClient(
        cast(
            SecretValueResponse,
            {},
        )
    )

    provider = AWSSecretsManagerSecretProvider(client)

    with pytest.raises(SecretValueFormatError):
        await provider.get_secret("invalid-secret")


@pytest.mark.asyncio
async def test_secret_name_must_not_be_empty() -> None:
    provider = EnvironmentSecretProvider({})

    with pytest.raises(
        ValueError,
        match="Secret name must not be empty",
    ):
        await provider.get_secret("   ")
