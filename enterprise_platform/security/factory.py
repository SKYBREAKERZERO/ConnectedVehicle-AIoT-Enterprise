from __future__ import annotations

from typing import cast

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.security.encryption import (
    KMSClient,
    KMSEncryptionProvider,
)
from enterprise_platform.security.secrets import (
    AWSSecretsManagerSecretProvider,
    SecretsManagerClient,
)


def create_aws_secrets_manager_provider(
    settings: Settings,
) -> AWSSecretsManagerSecretProvider:
    """Create a Secrets Manager provider using the platform AWS client factory."""

    client_factory = AWSClientFactory(settings)

    client = cast(
        SecretsManagerClient,
        client_factory.secrets_manager(),
    )

    return AWSSecretsManagerSecretProvider(client)


def create_kms_encryption_provider(
    settings: Settings,
    *,
    key_id: str,
) -> KMSEncryptionProvider:
    """Create a KMS provider using the platform AWS client factory."""

    client_factory = AWSClientFactory(settings)

    client = cast(
        KMSClient,
        client_factory.kms(),
    )

    return KMSEncryptionProvider(
        client,
        key_id=key_id,
    )
