from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3
import pytest
from sqlalchemy import text

from database.credential_journal import CredentialPreflightError
from database.credential_rotation import (
    PostgreSQLPasswords,
    Target,
    password_manager,
    recover,
    rotate,
)
from database.provision_tenant_local import provision_tenant
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import bootstrap_database_settings
from enterprise_platform.database.engine import create_database_engine
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
    settings = local_environment.model_copy(
        update={
            "credential_rotation_maintenance_mode": True,
            "database_tenant_id": "rotation-tenant",
            "application_database_secret_id": secrets["application"],
            "outbox_database_secret_id": secrets["outbox"],
            "remote_command_database_secret_id": secrets["remote-command"],
        }
    )
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


async def database_password_fingerprint(settings: Settings) -> str:
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.connect() as connection:
            rows = (
                await connection.execute(
                    text("SELECT rolname,rolpassword FROM pg_authid ORDER BY rolname")
                )
            ).all()
            # Never expose PostgreSQL password verifiers in assertions or evidence.
            return hashlib.sha256(json.dumps([tuple(row) for row in rows]).encode()).hexdigest()
    finally:
        await engine.dispose()


def secret_fingerprint(client: Any, targets: list[Target]) -> str:
    rows = []
    for target in targets:
        metadata = client.describe_secret(SecretId=target.secret_id)
        stages = metadata.get("VersionIdsToStages", {})
        values = {
            version: hashlib.sha256(
                client.get_secret_value(SecretId=target.secret_id, VersionId=version)[
                    "SecretString"
                ].encode()
            ).hexdigest()
            for version in stages
        }
        rows.append({"secret": target.secret_id, "stages": stages, "values": values})
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


@pytest.mark.integration
async def test_rejected_recovery_cannot_change_real_passwords_secrets_or_journals(
    local_environment: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    env = migration_environment(local_environment)
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=env,
        check=True,
        capture_output=True,
    )
    document = await provision_tenant(local_environment, "day14-recovery")
    roles, secrets = document["roles"], document["secrets"]
    assert isinstance(roles, dict) and isinstance(secrets, dict)
    targets = [
        Target(runtime, role, secrets[runtime], "day14-recovery") for runtime, role in roles.items()
    ]
    settings = local_environment.model_copy(
        update={
            "credential_rotation_maintenance_mode": True,
            "database_tenant_id": "day14-recovery",
            "application_database_secret_id": secrets["application"],
            "outbox_database_secret_id": secrets["outbox"],
            "remote_command_database_secret_id": secrets["remote-command"],
        }
    )
    client: Any = boto3.client(
        "secretsmanager",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    passwords = {target.role: "day14-new-" + target.role for target in targets}
    async with password_manager(settings, targets) as backend:
        original_set = backend.set_passwords
        writes = 0

        async def failed_compensation(values: dict[str, str | None]) -> None:
            nonlocal writes
            writes += 1
            if writes == 2:
                raise RuntimeError("Injected compensation failure")
            await original_set(values)

        monkeypatch.setattr(backend, "set_passwords", failed_compensation)
        with pytest.raises(RuntimeError, match="recovery required"):
            await rotate(
                settings,
                targets,
                passwords,
                FailingSecrets(client, "update_secret_version_stage"),
                backend,
                directory=tmp_path / "operation",
            )
    source = next((tmp_path / "operation").glob("*.json"))
    original_record = json.loads(source.read_text())
    mutations: list[tuple[str, list[Any], Any]] = [
        ("legacy-version", ["version"], 1),
        ("invalid-candidate", ["entries", 0, "candidate_version"], "invalid"),
        ("unknown-candidate", ["entries", 2, "candidate_version"], uuid4().hex),
        ("bootstrap-role", ["entries", 0, "target", "role"], "postgres"),
        ("migration-role", ["entries", 0, "target", "role"], "migration_owner"),
        ("foreign-secret", ["entries", 0, "target", "secret_id"], "/foreign/database/application"),
        ("wrong-host", ["database", "host"], "attacker.invalid"),
        ("wrong-port", ["database", "port"], settings.database_port + 1),
        ("wrong-database", ["database", "name"], "another_database"),
        ("wrong-environment", ["environment", "app_env"], "production"),
        ("wrong-tenant", ["environment", "tenant"], "victim"),
        ("wrong-region", ["environment", "aws_region"], "us-east-2"),
        ("wrong-endpoint", ["environment", "aws_endpoint_url"], "http://attacker.invalid:4566"),
        ("unknown-phase", ["phase"], "unsafe"),
        ("duplicate-entry", ["entries"], [original_record["entries"][0]] * 3),
        ("missing-runtime", ["entries"], original_record["entries"][:2]),
    ]
    db_before = await database_password_fingerprint(settings)
    cloud_before = secret_fingerprint(client, targets)
    update_calls = 0
    actual_set = PostgreSQLPasswords.set_passwords

    async def count_updates(self: PostgreSQLPasswords, values: dict[str, str | None]) -> None:
        nonlocal update_calls
        update_calls += 1
        await actual_set(self, values)

    monkeypatch.setattr(PostgreSQLPasswords, "set_passwords", count_updates)
    checked = []
    for case, route, value in mutations:
        record = deepcopy(original_record)
        parent: Any = record
        for component in route[:-1]:
            parent = parent[component]
        parent[route[-1]] = value
        path = tmp_path / f"rejected-{case}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        data = path.read_bytes()
        with pytest.raises(CredentialPreflightError):
            await recover(settings, path, client)
        assert update_calls == 0
        assert await database_password_fingerprint(settings) == db_before
        assert secret_fingerprint(client, targets) == cloud_before
        assert path.read_bytes() == data
        checked.append(case)
    # A syntactically valid version with another principal's payload must also
    # be rejected before touching any role, even after all earlier entries pass.
    entry = original_record["entries"][2]
    client.update_secret_version_stage(
        SecretId=targets[2].secret_id,
        VersionStage="DAY14_FIXTURE_RETAIN",
        MoveToVersionId=entry["candidate_version"],
    )
    bad_version = uuid4().hex
    foreign = {
        "engine": "postgres",
        "host": settings.database_host,
        "port": settings.database_port,
        "dbname": settings.database_name,
        "username": "migration_owner",
        "password": "fixture-only",
        "tenant_id": "day14-recovery",
    }
    client.put_secret_value(
        SecretId=targets[2].secret_id,
        ClientRequestToken=bad_version,
        SecretString=json.dumps(foreign),
        VersionStages=["AWSPENDING"],
    )
    bad = deepcopy(original_record)
    bad["entries"][2]["candidate_version"] = bad_version
    path = tmp_path / "rejected-foreign-payload.json"
    path.write_text(json.dumps(bad))
    data = path.read_bytes()
    bad_cloud = secret_fingerprint(client, targets)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, client)
    assert update_calls == 0 and await database_password_fingerprint(settings) == db_before
    assert secret_fingerprint(client, targets) == bad_cloud and path.read_bytes() == data
    checked.append("foreign-version-payload")
    client.update_secret_version_stage(
        SecretId=targets[2].secret_id,
        VersionStage="AWSPENDING",
        MoveToVersionId=entry["candidate_version"],
        RemoveFromVersionId=bad_version,
    )
    await recover(settings, source, client)
    assert update_calls == 1
    restored_db = await database_password_fingerprint(settings)
    restored_cloud = secret_fingerprint(client, targets)
    restored_journal = source.read_bytes()
    await recover(settings, source, client)
    assert update_calls == 1
    assert await database_password_fingerprint(settings) == restored_db
    assert (
        secret_fingerprint(client, targets) == restored_cloud
        and source.read_bytes() == restored_journal
    )
    # Removing a container is deliberate fixture setup. Neither rotation nor
    # recovery may recreate it or change a password in response.
    client.delete_secret(SecretId=targets[2].secret_id, ForceDeleteWithoutRecovery=True)
    missing_db = await database_password_fingerprint(settings)
    remaining_cloud = secret_fingerprint(client, targets[:2])
    async with password_manager(settings, targets) as backend:
        with pytest.raises(CredentialPreflightError, match="Terraform"):
            await rotate(
                settings, targets, passwords, client, backend, directory=tmp_path / "missing"
            )
    assert update_calls == 1 and await database_password_fingerprint(settings) == missing_db
    assert secret_fingerprint(client, targets[:2]) == remaining_cloud
    missing_path = tmp_path / "missing-secret-recovery.json"
    missing_path.write_text(json.dumps(original_record))
    missing_bytes = missing_path.read_bytes()
    with pytest.raises(CredentialPreflightError, match="Terraform"):
        await recover(settings, missing_path, client)
    assert update_calls == 1 and await database_password_fingerprint(settings) == missing_db
    assert missing_path.read_bytes() == missing_bytes
    with pytest.raises(client.exceptions.ResourceNotFoundException):
        client.describe_secret(SecretId=targets[2].secret_id)
    evidence(
        "credential-recovery-hardening",
        {
            "scope": "localstack-and-postgresql",
            "journal_version": 2,
            "invalid_cases": checked,
            "invalid_journal_no_side_effects": True,
            "missing_secret_not_created": True,
            "missing_secret_no_password_changes": True,
            "compensation_failure_observed": True,
            "explicit_recovery_succeeded": True,
            "repeated_recovery_no_side_effects": True,
            "iam_enforcement_verified": False,
        },
    )
