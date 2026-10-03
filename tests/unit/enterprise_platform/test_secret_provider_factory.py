from __future__ import annotations

from unittest.mock import Mock, patch

from botocore.client import BaseClient

from enterprise_platform.config.settings import Settings
from enterprise_platform.security.factory import (
    create_aws_secrets_manager_provider,
    create_kms_encryption_provider,
)
from enterprise_platform.security.secrets import (
    AWSSecretsManagerSecretProvider,
)


def test_create_aws_secrets_manager_provider_uses_platform_client_factory() -> None:
    settings = Settings()

    fake_client = Mock(spec=BaseClient)

    with patch("enterprise_platform.security.factory.AWSClientFactory") as factory_type:
        factory = factory_type.return_value
        factory.secrets_manager.return_value = fake_client

        provider = create_aws_secrets_manager_provider(settings)

    assert isinstance(
        provider,
        AWSSecretsManagerSecretProvider,
    )

    factory_type.assert_called_once_with(settings)
    factory.secrets_manager.assert_called_once_with()


def test_create_kms_encryption_provider_uses_platform_client_factory() -> None:
    settings = Settings()

    fake_client = Mock(spec=BaseClient)

    with patch("enterprise_platform.security.factory.AWSClientFactory") as factory_type:
        factory = factory_type.return_value
        factory.kms.return_value = fake_client

        provider = create_kms_encryption_provider(
            settings,
            key_id="key-001",
        )

    assert provider.key_id == "key-001"

    factory_type.assert_called_once_with(settings)
    factory.kms.assert_called_once_with()
