from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from enterprise_platform.security.encryption import (
    EncryptionAccessError,
    EncryptionBackendError,
    EncryptionKeyNotFoundError,
    InvalidCiphertextError,
    KMSDecryptResponse,
    KMSEncryptionProvider,
    KMSEncryptResponse,
)


class FakeKMSClient:
    def __init__(self) -> None:
        self.encrypt_key_id: str | None = None
        self.decrypt_key_id: str | None = None
        self.encrypt_context: dict[str, str] | None = None
        self.decrypt_context: dict[str, str] | None = None

    def encrypt(
        self,
        *,
        KeyId: str,
        Plaintext: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSEncryptResponse:
        self.encrypt_key_id = KeyId
        self.encrypt_context = EncryptionContext

        return {
            "CiphertextBlob": b"kms:" + Plaintext,
            "KeyId": KeyId,
        }

    def decrypt(
        self,
        *,
        KeyId: str,
        CiphertextBlob: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSDecryptResponse:
        self.decrypt_key_id = KeyId
        self.decrypt_context = EncryptionContext

        return {
            "Plaintext": CiphertextBlob.removeprefix(b"kms:"),
            "KeyId": KeyId,
        }


class FailingKMSClient:
    def __init__(
        self,
        error_code: str,
    ) -> None:
        self._error_code = error_code

    def _raise(self, operation: str) -> None:
        raise ClientError(
            {
                "Error": {
                    "Code": self._error_code,
                    "Message": ("sensitive-backend-detail-must-not-leak"),
                }
            },
            operation,
        )

    def encrypt(
        self,
        *,
        KeyId: str,
        Plaintext: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSEncryptResponse:
        del KeyId, Plaintext, EncryptionContext
        self._raise("Encrypt")
        raise AssertionError("unreachable")

    def decrypt(
        self,
        *,
        KeyId: str,
        CiphertextBlob: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSDecryptResponse:
        del KeyId, CiphertextBlob, EncryptionContext
        self._raise("Decrypt")
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_kms_provider_encrypts_and_decrypts() -> None:
    client = FakeKMSClient()

    provider = KMSEncryptionProvider(
        client,
        key_id="  key-001  ",
    )

    ciphertext = await provider.encrypt(b"vehicle-secret")

    plaintext = await provider.decrypt(ciphertext)

    assert provider.key_id == "key-001"
    assert ciphertext == b"kms:vehicle-secret"
    assert plaintext == b"vehicle-secret"
    assert client.encrypt_key_id == "key-001"
    assert client.decrypt_key_id == "key-001"


@pytest.mark.asyncio
async def test_kms_provider_preserves_encryption_context() -> None:
    client = FakeKMSClient()

    provider = KMSEncryptionProvider(
        client,
        key_id="key-001",
    )

    context = {
        "resource": "vehicle",
        "purpose": "integration",
    }

    ciphertext = await provider.encrypt(
        b"vehicle-secret",
        encryption_context=context,
    )

    await provider.decrypt(
        ciphertext,
        encryption_context=context,
    )

    assert client.encrypt_context == context
    assert client.decrypt_context == context


def test_kms_provider_rejects_empty_key_id() -> None:
    with pytest.raises(
        ValueError,
        match="KMS key ID must not be empty",
    ):
        KMSEncryptionProvider(
            FakeKMSClient(),
            key_id="   ",
        )


@pytest.mark.asyncio
async def test_kms_provider_rejects_empty_plaintext() -> None:
    provider = KMSEncryptionProvider(
        FakeKMSClient(),
        key_id="key-001",
    )

    with pytest.raises(
        ValueError,
        match="Plaintext must not be empty",
    ):
        await provider.encrypt(b"")


@pytest.mark.asyncio
async def test_kms_provider_rejects_empty_ciphertext() -> None:
    provider = KMSEncryptionProvider(
        FakeKMSClient(),
        key_id="key-001",
    )

    with pytest.raises(
        ValueError,
        match="Ciphertext must not be empty",
    ):
        await provider.decrypt(b"")


@pytest.mark.asyncio
async def test_kms_provider_maps_missing_key() -> None:
    provider = KMSEncryptionProvider(
        FailingKMSClient("NotFoundException"),
        key_id="missing-key",
    )

    with pytest.raises(EncryptionKeyNotFoundError):
        await provider.encrypt(b"secret-value")


@pytest.mark.asyncio
async def test_kms_provider_maps_access_denied() -> None:
    provider = KMSEncryptionProvider(
        FailingKMSClient("AccessDeniedException"),
        key_id="protected-key",
    )

    with pytest.raises(EncryptionAccessError) as exc_info:
        await provider.encrypt(b"secret-value")

    assert "sensitive-backend-detail" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kms_provider_maps_invalid_ciphertext() -> None:
    provider = KMSEncryptionProvider(
        FailingKMSClient("InvalidCiphertextException"),
        key_id="key-001",
    )

    with pytest.raises(InvalidCiphertextError):
        await provider.decrypt(b"invalid-ciphertext")


@pytest.mark.asyncio
async def test_kms_provider_hides_unexpected_backend_details() -> None:
    provider = KMSEncryptionProvider(
        FailingKMSClient("InternalException"),
        key_id="key-001",
    )

    with pytest.raises(EncryptionBackendError) as exc_info:
        await provider.encrypt(b"super-sensitive-plaintext")

    message = str(exc_info.value)

    assert "super-sensitive-plaintext" not in message
    assert "sensitive-backend-detail" not in message
