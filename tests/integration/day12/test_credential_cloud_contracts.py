from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import boto3
import pytest

from database.credential_rotation import Target, password_manager, retire, rotate
from database.provision_tenant_local import provision_tenant
from enterprise_platform.config.settings import Settings
from scripts.verify_tenant_local import verify
from tests.integration.day12.conftest import evidence, migration_environment
from tests.integration.day12.test_credential_rotation import (
    FailingSecrets,
    database_password_fingerprint,
)


async def prepare(settings: Settings, tenant: str) -> tuple[Any, list[Target], Settings, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=migration_environment(settings),
        capture_output=True,
    )
    assert result.returncode == 0, "Migration failed"
    document = await provision_tenant(settings, tenant)
    roles, secrets = document["roles"], document["secrets"]
    assert isinstance(roles, dict) and isinstance(secrets, dict)
    configured = settings.model_copy(
        update={
            "credential_rotation_maintenance_mode": True,
            "database_tenant_id": tenant,
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
    targets = [Target(runtime, role, secrets[runtime], tenant) for runtime, role in roles.items()]
    return document, targets, configured, client


class PausedCloud:
    def __init__(
        self,
        client: Any,
        case: str,
        targets: list[Target],
        started: threading.Event,
        release: threading.Event,
    ) -> None:
        self.client, self.case, self.targets = client, case, targets
        self.started, self.release = started, release
        self.paused = False

    def __getattr__(self, method: str) -> Any:
        original = getattr(self.client, method)

        def call(**kwargs: Any) -> Any:
            response = original(**kwargs)
            stop = (
                self.case == "prepare-pending"
                and method == "put_secret_value"
                and kwargs["SecretId"] == self.targets[-1].secret_id
            ) or (
                self.case == "promotion-current"
                and method == "update_secret_version_stage"
                and kwargs.get("VersionStage") == "AWSCURRENT"
                and kwargs["SecretId"] == self.targets[0].secret_id
            )
            if stop and not self.paused:
                self.paused = True
                self.started.set()
                assert self.release.wait(10)
            return response

        return call


async def managed_rotation(
    settings: Settings, targets: list[Target], client: Any, directory: Path
) -> None:
    async with password_manager(settings, targets) as backend:
        await rotate(
            settings,
            targets,
            {t.role: "managed-" + t.role for t in targets},
            client,
            backend,
            directory=directory,
        )


@pytest.mark.integration
async def test_external_localstack_version_competition_during_real_management_lock(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    cases = []
    for case in ("prepare-pending", "promotion-current"):
        _, targets, settings, client = await prepare(local_environment, "competition-" + case)
        started, release = threading.Event(), threading.Event()

        paused = PausedCloud(client, case, targets, started, release)
        directory = tmp_path / case
        task = asyncio.create_task(managed_rotation(settings, targets, paused, directory))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            # An actual second SDK client bypasses the DB lock, emulating an external publisher.
            external: Any = boto3.client(
                "secretsmanager",
                endpoint_url=settings.aws_endpoint_url,
                region_name=settings.aws_region,
                aws_access_key_id="test",
                aws_secret_access_key="test",
            )
            target = targets[0] if case == "prepare-pending" else targets[-1]
            before = await database_password_fingerprint(settings)
            value = {
                "engine": "postgres",
                "host": settings.database_host,
                "port": settings.database_port,
                "dbname": settings.database_name,
                "username": target.role,
                "tenant_id": target.tenant,
                "password": "external-fixture-password",
            }
            stage = "AWSPENDING" if case == "prepare-pending" else "AWSCURRENT"
            foreign = await asyncio.to_thread(
                external.put_secret_value,
                SecretId=target.secret_id,
                SecretString=json.dumps(value),
                VersionStages=[stage],
            )
            foreign_version = foreign["VersionId"]
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="recovery required"):
            await task
        assert await database_password_fingerprint(settings) == before
        labels = client.describe_secret(SecretId=target.secret_id)["VersionIdsToStages"]
        assert stage in labels[foreign_version]
        record = json.loads(next(directory.glob("*.json")).read_text())
        assert record["phase"] == "recovery_required"
        cases.append(
            {
                "case": case,
                "database_unchanged_after_barrier": True,
                "foreign_version_preserved": True,
                "unresolved_operation_recorded": True,
            }
        )
    evidence(
        "credential-version-competition",
        {
            "scope": "localstack-and-postgresql",
            "cases": cases,
            "iam_enforcement_verified": False,
        },
    )


def cloud_snapshot(document: Any, manager: Any, kms: Any, iam: Any) -> str:
    rows = []
    for identity in document["identities"].values():
        name = identity["role_arn"].rsplit("/", 1)[1]
        role = iam.get_role(RoleName=name)["Role"]
        rows.append(
            {
                "role_id": role["RoleId"],
                "trust": role["AssumeRolePolicyDocument"],
                "policy": iam.get_role_policy(RoleName=name, PolicyName="own-database-secret")[
                    "PolicyDocument"
                ],
                "key": manager.describe_secret(SecretId=identity["secret_arn"])["KmsKeyId"],
            }
        )
    value = {
        "roles": rows,
        "enabled": kms.describe_key(KeyId=document["kms_key_arn"])["KeyMetadata"]["Enabled"],
        "rotation": kms.get_key_rotation_status(KeyId=document["kms_key_arn"])[
            "KeyRotationEnabled"
        ],
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


@pytest.mark.integration
async def test_kms_iam_contracts_across_creation_rotation_recovery_and_retirement(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    document, targets, settings, manager = await prepare(local_environment, "cloud-lifecycle")
    arguments: dict[str, Any] = dict(
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    kms: Any = boto3.client("kms", **arguments)
    iam: Any = boto3.client("iam", **arguments)
    snapshot = cloud_snapshot(document, manager, kms, iam)
    stages = []

    async def check(stage: str) -> None:
        result = await verify(cast(Any, document), settings)
        assert result["iam_enforcement_verified"] is False
        assert result["iam_policy_configuration"] == "passed"
        assert result["kms_context_roundtrip"] == "passed"
        assert cloud_snapshot(document, manager, kms, iam) == snapshot
        stages.append(stage)

    await check("created")
    async with password_manager(settings, targets) as backend:
        success = await rotate(
            settings,
            targets,
            {t.role: "cloud-new-" + t.role for t in targets},
            manager,
            backend,
            directory=tmp_path / "success",
        )
    await check("rotated")
    async with password_manager(settings, targets) as backend:
        with pytest.raises(RuntimeError, match="was recovered"):
            await rotate(
                settings,
                targets,
                {t.role: "cloud-failed-" + t.role for t in targets},
                FailingSecrets(manager, "update_secret_version_stage"),
                backend,
                directory=tmp_path / "failure",
            )
    await check("recovered")
    record = json.loads(success.read_text())
    for entry in record["entries"]:
        manager.update_secret_version_stage(
            SecretId=entry["target"]["secret_id"],
            VersionStage="AWSPENDING",
            MoveToVersionId=entry["candidate_version"],
        )
    await retire(settings, success, manager)
    await check("retired")

    # These are configuration/crypto probes, not an AWS IAM enforcement simulation.
    key = document["kms_key_arn"]
    kms.disable_key_rotation(KeyId=key)
    try:
        with pytest.raises(RuntimeError, match="security contract"):
            await verify(cast(Any, document), settings)
    finally:
        kms.enable_key_rotation(KeyId=key)
    kms.disable_key(KeyId=key)
    try:
        with pytest.raises(RuntimeError, match="security contract"):
            await verify(cast(Any, document), settings)
    finally:
        kms.enable_key(KeyId=key)
    identity = document["identities"]["application"]
    name = identity["role_arn"].rsplit("/", 1)[1]
    policy = iam.get_role_policy(RoleName=name, PolicyName="own-database-secret")["PolicyDocument"]
    broadened = deepcopy(policy)
    broadened["Statement"][0]["Resource"] = "*"
    iam.put_role_policy(
        RoleName=name, PolicyName="own-database-secret", PolicyDocument=json.dumps(broadened)
    )
    try:
        with pytest.raises(RuntimeError, match="security contract"):
            await verify(cast(Any, document), settings)
    finally:
        iam.put_role_policy(
            RoleName=name, PolicyName="own-database-secret", PolicyDocument=json.dumps(policy)
        )
    iam.delete_role_policy(RoleName=name, PolicyName="own-database-secret")
    try:
        with pytest.raises(RuntimeError, match="security contract"):
            await verify(cast(Any, document), settings)
    finally:
        iam.put_role_policy(
            RoleName=name, PolicyName="own-database-secret", PolicyDocument=json.dumps(policy)
        )
    kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
    try:
        metadata = kms.describe_key(KeyId=key)["KeyMetadata"]
        assert metadata["KeyState"] == "PendingDeletion"
        with pytest.raises(RuntimeError, match="security contract"):
            await verify(cast(Any, document), settings)
    finally:
        kms.cancel_key_deletion(KeyId=key)
        kms.enable_key(KeyId=key)
    assert cloud_snapshot(document, manager, kms, iam) == snapshot
    evidence(
        "credential-cloud-lifecycle",
        {
            "scope": "localstack-only",
            "stages": stages,
            "configuration_preserved": True,
            "kms_context_verified": True,
            "disabled_key_rejected": True,
            "disabled_rotation_rejected": True,
            "pending_key_deletion_rejected": True,
            "revoked_iam_policy_rejected": True,
            "wildcard_policy_rejected": True,
            "iam_enforcement_verified": False,
        },
    )
