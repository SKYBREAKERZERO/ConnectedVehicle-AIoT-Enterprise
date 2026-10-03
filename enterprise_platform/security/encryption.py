from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import NotRequired, Protocol, TypedDict

from botocore.exceptions import ClientError


class KMSEncryptResponse(TypedDict):
    CiphertextBlob: NotRequired[bytes]
    KeyId: NotRequired[str]


class KMSDecryptResponse(TypedDict):
    Plaintext: NotRequired[bytes]
    KeyId: NotRequired[str]


class KMSClient(Protocol):
    def encrypt(
        self,
        *,
        KeyId: str,
        Plaintext: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSEncryptResponse: ...

    def decrypt(
        self,
        *,
        KeyId: str,
        CiphertextBlob: bytes,
        EncryptionContext: dict[str, str] | None = None,
    ) -> KMSDecryptResponse: ...


class EncryptionProvider(Protocol):
    async def encrypt(
        self,
        plaintext: bytes,
        *,
        encryption_context: Mapping[str, str] | None = None,
    ) -> bytes: ...

    async def decrypt(
        self,
        ciphertext: bytes,
        *,
        encryption_context: Mapping[str, str] | None = None,
    ) -> bytes: ...


class EncryptionProviderError(Exception):
    """Base exception for encryption provider failures."""


class EncryptionKeyNotFoundError(EncryptionProviderError):
    """Raised when the configured encryption key does not exist."""

    def __init__(self) -> None:
        super().__init__("The encryption key was not found.")


class EncryptionAccessError(EncryptionProviderError):
    """Raised when the backend denies an encryption operation."""

    def __init__(self, operation: str) -> None:
        self.operation = operation

        super().__init__(f"The encryption backend denied the '{operation}' operation.")


class EncryptionBackendError(EncryptionProviderError):
    """Raised for unexpected encryption backend failures."""

    def __init__(self, operation: str) -> None:
        self.operation = operation

        super().__init__(f"The encryption backend failed during '{operation}'.")


class InvalidCiphertextError(EncryptionProviderError):
    """Raised when ciphertext cannot be decrypted."""

    def __init__(self) -> None:
        super().__init__("The ciphertext could not be decrypted.")


class EncryptionValueFormatError(EncryptionProviderError):
    """Raised when the backend returns an invalid payload."""

    def __init__(self, operation: str) -> None:
        self.operation = operation

        super().__init__(f"The encryption backend returned an invalid '{operation}' response.")


def normalize_kms_key_id(key_id: str) -> str:
    normalized = key_id.strip()

    if not normalized:
        raise ValueError("KMS key ID must not be empty.")

    return normalized


class KMSEncryptionProvider:
    """Encryption provider backed by AWS KMS."""

    def __init__(
        self,
        client: KMSClient,
        *,
        key_id: str,
    ) -> None:
        self._client = client
        self._key_id = normalize_kms_key_id(key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    async def encrypt(
        self,
        plaintext: bytes,
        *,
        encryption_context: Mapping[str, str] | None = None,
    ) -> bytes:
        if not plaintext:
            raise ValueError("Plaintext must not be empty.")

        try:
            if encryption_context:
                response = await asyncio.to_thread(
                    self._client.encrypt,
                    KeyId=self._key_id,
                    Plaintext=plaintext,
                    EncryptionContext=dict(encryption_context),
                )
            else:
                response = await asyncio.to_thread(
                    self._client.encrypt,
                    KeyId=self._key_id,
                    Plaintext=plaintext,
                )
        except ClientError as exc:
            self._raise_mapped_client_error(
                exc,
                operation="encrypt",
            )

        ciphertext = response.get("CiphertextBlob")

        if not ciphertext:
            raise EncryptionValueFormatError("encrypt")

        return ciphertext

    async def decrypt(
        self,
        ciphertext: bytes,
        *,
        encryption_context: Mapping[str, str] | None = None,
    ) -> bytes:
        if not ciphertext:
            raise ValueError("Ciphertext must not be empty.")

        try:
            if encryption_context:
                response = await asyncio.to_thread(
                    self._client.decrypt,
                    KeyId=self._key_id,
                    CiphertextBlob=ciphertext,
                    EncryptionContext=dict(encryption_context),
                )
            else:
                response = await asyncio.to_thread(
                    self._client.decrypt,
                    KeyId=self._key_id,
                    CiphertextBlob=ciphertext,
                )
        except ClientError as exc:
            self._raise_mapped_client_error(
                exc,
                operation="decrypt",
            )

        plaintext = response.get("Plaintext")

        if plaintext is None:
            raise EncryptionValueFormatError("decrypt")

        return plaintext

    @staticmethod
    def _raise_mapped_client_error(
        exc: ClientError,
        *,
        operation: str,
    ) -> None:
        error_code = str(
            exc.response.get("Error", {}).get(
                "Code",
                "",
            )
        )

        if error_code == "NotFoundException":
            raise EncryptionKeyNotFoundError() from exc

        if error_code == "InvalidCiphertextException":
            raise InvalidCiphertextError() from exc

        if error_code in {
            "AccessDeniedException",
            "DisabledException",
            "KMSInvalidStateException",
        }:
            raise EncryptionAccessError(operation) from exc

        raise EncryptionBackendError(operation) from exc
