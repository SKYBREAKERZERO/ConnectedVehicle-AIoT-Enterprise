from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import boto3
import pytest

from database.credential_rotation import Target, password_manager, recover, rotate
from database.provision_tenant_local import provision_tenant
from enterprise_platform.config.settings import Settings
from tests.integration.day12.conftest import evidence, migration_environment


class FailingSecrets:
    def __init__(self, client: Any, method: str) -> None:
        self.client, self.method, self.count = client, method, 0

    def __getattr__(self, name: str) -> Any:
        original = getattr(self.client, name)
        if name != self.method:
            return original

        def call(**kwargs: Any) -> Any:
            self.count += 1
            if self.count == 2:
                raise RuntimeError("injected publication failure")
            return original(**kwargs)

        return call


@pytest.mark.integration
async def test_actual_database_and_localstack_rotation_failure_recovery(
    local_environment: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=migration_environment(local_environment),
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, (
        result.stderr.decode(errors="replace")
        .replace("test-migration", "[redacted]")
        .replace("test-admin", "[redacted]")
    )
    document = await provision_tenant(local_environment, "rotation-tenant")
    roles, secrets = document["roles"], document["secrets"]
    assert isinstance(roles, dict) and isinstance(secrets, dict)
    targets = [
        Target(runtime, role, secrets[runtime], "rotation-tenant")
        for runtime, role in roles.items()
    ]
    client: Any = boto3.client(
        "secretsmanager",
        endpoint_url=local_environment.aws_endpoint_url,
        region_name=local_environment.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    settings = local_environment.model_copy(update={"credential_rotation_maintenance_mode": True})
    passwords = {target.role: "new-" + target.role for target in targets}
    original = {
        target.secret_id: client.get_secret_value(SecretId=target.secret_id) for target in targets
    }
    scenarios = []
    for method in ("put_secret_value", "update_secret_version_stage"):
        directory = tmp_path / method
        async with password_manager(settings, targets) as backend:
            with pytest.raises(RuntimeError, match="was recovered"):
                await rotate(
                    settings,
                    targets,
                    passwords,
                    FailingSecrets(client, method),
                    backend,
                    directory=directory,
                )
            for target in targets:
                current = client.get_secret_value(SecretId=target.secret_id)
                assert current["VersionId"] == original[target.secret_id]["VersionId"]
                assert current["SecretString"] == original[target.secret_id]["SecretString"]
                await backend.verify(target, json.loads(current["SecretString"]))
        journal = next(directory.glob("*.json"))
        assert json.loads(journal.read_text())["phase"] == "recovered"
        scenarios.append({"failure": method, "passwords_and_current_restored": True})
    directory = tmp_path / "recovery-required"
    async with password_manager(settings, targets) as backend:
        original_set = backend.set_passwords
        writes = 0

        async def failed_rollback(values: dict[str, str | None]) -> None:
            nonlocal writes
            writes += 1
            if writes == 2:
                raise RuntimeError("injected database recovery failure")
            await original_set(values)

        monkeypatch.setattr(backend, "set_passwords", failed_rollback)
        with pytest.raises(RuntimeError, match="recovery required"):
            await rotate(
                settings,
                targets,
                passwords,
                FailingSecrets(client, "update_secret_version_stage"),
                backend,
                directory=directory,
            )
    journal = next(directory.glob("*.json"))
    assert json.loads(journal.read_text())["phase"] == "recovery_required"
    await recover(settings, journal, client)
    assert json.loads(journal.read_text())["phase"] == "recovered"
    async with password_manager(settings, targets) as backend:
        for target in targets:
            current = client.get_secret_value(SecretId=target.secret_id)
            assert current["VersionId"] == original[target.secret_id]["VersionId"]
            await backend.verify(target, json.loads(current["SecretString"]))
        success = await rotate(
            settings, targets, passwords, client, backend, directory=tmp_path / "success"
        )
        assert json.loads(success.read_text())["phase"] == "complete"
    for path in tmp_path.rglob("*.json"):
        assert all(password not in path.read_text() for password in passwords.values())
    evidence(
        "credential-rotation",
        {
            "scope": "localstack-and-postgresql",
            "roles": len(targets),
            "failure_cases": scenarios,
            "explicit_recovery": True,
            "retry_succeeded": True,
            "journals_secret_free": True,
            "iam_enforcement_verified": False,
        },
    )
