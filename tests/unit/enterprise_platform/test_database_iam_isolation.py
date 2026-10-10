from __future__ import annotations

from pathlib import Path


def test_terraform_runtime_policies_are_isolated() -> None:
    source = Path("infra/terraform/environments/local/main.tf").read_text()
    for policy, secret in [
        ("application_secret_read_policy", "database_application"),
        ("outbox_dispatcher_secret_read_policy", "database_outbox"),
        ("remote_command_dispatcher_secret_read_policy", "database_remote_command"),
    ]:
        block = source.split(f'module "{policy}" {{', 1)[1].split("\nresource ", 1)[0]
        for candidate in ("database_application", "database_outbox", "database_remote_command"):
            assert (f'["{candidate}"]' in block) == (candidate == secret)
        assert "kms:EncryptionContext:SecretARN" in block
        assert '"secretsmanager:GetSecretValue"' in block
        assert '"secretsmanager:PutSecretValue"' not in block
