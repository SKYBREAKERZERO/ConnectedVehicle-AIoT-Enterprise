from __future__ import annotations

from typing import Protocol, TypedDict, cast

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.security.encryption import (
    InvalidCiphertextError,
)
from enterprise_platform.security.factory import (
    create_kms_encryption_provider,
)


class KMSKeyMetadata(TypedDict):
    KeyId: str


class KMSCreateKeyResponse(TypedDict):
    KeyMetadata: KMSKeyMetadata


class KMSIntegrationClient(Protocol):
    def create_key(
        self,
        *,
        Description: str,
        KeyUsage: str,
        KeySpec: str,
    ) -> KMSCreateKeyResponse: ...

    def disable_key(
        self,
        *,
        KeyId: str,
    ) -> object: ...

    def schedule_key_deletion(
        self,
        *,
        KeyId: str,
        PendingWindowInDays: int,
    ) -> object: ...


@pytest.mark.asyncio
async def test_localstack_kms_encrypt_decrypt_round_trip() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK

    client = cast(
        KMSIntegrationClient,
        AWSClientFactory(settings).kms(),
    )

    key_id: str | None = None

    try:
        create_response = client.create_key(
            Description=("Connected Vehicle integration test key"),
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
        )

        key_id = create_response["KeyMetadata"]["KeyId"]

        provider = create_kms_encryption_provider(
            settings,
            key_id=key_id,
        )

        plaintext = b"connected-vehicle-sensitive-value"

        context = {
            "application": "connected-vehicle",
            "purpose": "integration-test",
        }

        ciphertext = await provider.encrypt(
            plaintext,
            encryption_context=context,
        )

        assert ciphertext != plaintext
        assert plaintext not in ciphertext

        decrypted = await provider.decrypt(
            ciphertext,
            encryption_context=context,
        )

        assert decrypted == plaintext

        with pytest.raises(InvalidCiphertextError):
            await provider.decrypt(
                ciphertext,
                encryption_context={
                    "application": "connected-vehicle",
                    "purpose": "wrong-context",
                },
            )

    finally:
        if key_id is not None:
            client.disable_key(
                KeyId=key_id,
            )

            client.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=7,
            )
