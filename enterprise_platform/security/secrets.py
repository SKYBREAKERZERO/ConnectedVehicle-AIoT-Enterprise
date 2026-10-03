from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from typing import NotRequired, Protocol, TypedDict

from botocore.exceptions import ClientError


class SecretValueResponse(TypedDict):
    SecretString: NotRequired[str]
    SecretBinary: NotRequired[bytes]


class SecretsManagerClient(Protocol):
    def get_secret_value(
        self,
        *,
        SecretId: str,
    ) -> SecretValueResponse: ...


class SecretProvider(Protocol):
    async def get_secret(
        self,
        name: str,
    ) -> str: ...


class SecretProviderError(Exception):
    """Base exception for secret provider failures."""


class SecretNotFoundError(SecretProviderError):
    """Raised when a requested secret does not exist."""

    def __init__(self, name: str) -> None:
        self.name = name

        super().__init__(f"Secret '{name}' was not found.")


class SecretAccessError(SecretProviderError):
    """Raised when the secret backend cannot be accessed."""

    def __init__(self, name: str) -> None:
        self.name = name

        super().__init__(f"Secret '{name}' could not be retrieved.")


class SecretValueFormatError(SecretProviderError):
    """Raised when a secret has no supported value representation."""

    def __init__(self, name: str) -> None:
        self.name = name

        super().__init__(f"Secret '{name}' has an unsupported value format.")


def normalize_secret_name(name: str) -> str:
    normalized = name.strip()

    if not normalized:
        raise ValueError("Secret name must not be empty.")

    return normalized


class EnvironmentSecretProvider:
    """Secret provider backed by environment variables.

    Intended for local development and controlled test environments.
    """

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._environ = environ if environ is not None else os.environ

    async def get_secret(
        self,
        name: str,
    ) -> str:
        normalized_name = normalize_secret_name(name)

        try:
            value = self._environ[normalized_name]
        except KeyError as exc:
            raise SecretNotFoundError(normalized_name) from exc

        if not value:
            raise SecretValueFormatError(normalized_name)

        return value


class AWSSecretsManagerSecretProvider:
    """Secret provider backed by AWS Secrets Manager."""

    def __init__(
        self,
        client: SecretsManagerClient,
    ) -> None:
        self._client = client

    async def get_secret(
        self,
        name: str,
    ) -> str:
        normalized_name = normalize_secret_name(name)

        try:
            response = await asyncio.to_thread(
                self._client.get_secret_value,
                SecretId=normalized_name,
            )
        except ClientError as exc:
            error_code = str(
                exc.response.get("Error", {}).get(
                    "Code",
                    "",
                )
            )

            if error_code == "ResourceNotFoundException":
                raise SecretNotFoundError(normalized_name) from exc

            raise SecretAccessError(normalized_name) from exc

        secret_string = response.get("SecretString")

        if secret_string is not None:
            if not secret_string:
                raise SecretValueFormatError(normalized_name)

            return secret_string

        secret_binary = response.get("SecretBinary")

        if secret_binary is None:
            raise SecretValueFormatError(normalized_name)

        try:
            value = secret_binary.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecretValueFormatError(normalized_name) from exc

        if not value:
            raise SecretValueFormatError(normalized_name)

        return value
