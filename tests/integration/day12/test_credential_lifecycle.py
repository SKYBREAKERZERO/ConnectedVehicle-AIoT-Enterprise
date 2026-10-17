from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from collections.abc import Awaitable, Callable
from contextlib import suppress
from copy import deepcopy
from pathlib import Path
from typing import Any

import boto3
import pytest
from sqlalchemy import text

from database.credential_journal import CredentialPreflightError, load_journal
from database.credential_rotation import (
    Target,
    password_manager,
    recover,
    request,
    retire,
    rotate,
    save_journal,
)
from database.provision_tenant_local import provision_tenant
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import bootstrap_database_settings
from enterprise_platform.database.engine import create_database_engine
from tests.integration.day12.conftest import evidence, migration_environment
from tests.integration.day12.test_credential_rotation import database_password_fingerprint


@pytest.mark.integration
async def test_postgresql_localstack_credential_lifecycle(
    local_environment: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=migration_environment(local_environment),
        capture_output=True,
    )
    assert result.returncode == 0, "Migration failed"
    document = await provision_tenant(local_environment, "day15-lifecycle")
    roles, secrets = document["roles"], document["secrets"]
    assert isinstance(roles, dict) and isinstance(secrets, dict)
    targets = [
        Target(runtime, role, secrets[runtime], "day15-lifecycle")
        for runtime, role in roles.items()
    ]
    settings = local_environment.model_copy(
        update={
            "credential_rotation_maintenance_mode": True,
            "database_tenant_id": "day15-lifecycle",
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
    passwords = {target.role: "day15-candidate-" + target.role for target in targets}
    target = targets[2]
    foreign = client.put_secret_value(
        SecretId=target.secret_id,
        SecretString='{"password":"foreign-pending"}',
        VersionStages=["AWSPENDING"],
    )["VersionId"]
    before_passwords = await database_password_fingerprint(settings)
    before_labels = {
        t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        for t in targets
    }
    async with password_manager(settings, targets) as backend:
        with pytest.raises(CredentialPreflightError, match="Pending"):
            await rotate(
                settings, targets, passwords, client, backend, directory=tmp_path / "blocked"
            )
    assert await database_password_fingerprint(settings) == before_passwords
    assert {
        t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        for t in targets
    } == before_labels
    assert not (tmp_path / "blocked").exists()
    client.update_secret_version_stage(
        SecretId=target.secret_id, VersionStage="AWSPENDING", RemoveFromVersionId=foreign
    )
    client.delete_secret(SecretId=target.secret_id, RecoveryWindowInDays=7)
    async with password_manager(settings, targets) as backend:
        with pytest.raises(CredentialPreflightError, match="deletion"):
            await rotate(
                settings, targets, passwords, client, backend, directory=tmp_path / "deleted"
            )
    assert await database_password_fingerprint(settings) == before_passwords
    assert not (tmp_path / "deleted").exists()
    client.restore_secret(SecretId=target.secret_id)

    removals = 0

    class CleanupFailure:
        def __getattr__(self, name: str) -> Any:
            original = getattr(client, name)
            if name != "update_secret_version_stage":
                return original

            def call(**kwargs: Any) -> Any:
                nonlocal removals
                if kwargs["VersionStage"] == "AWSPENDING":
                    removals += 1
                    if removals == 2:
                        raise RuntimeError("injected retirement failure")
                return original(**kwargs)

            return call

    async with password_manager(settings, targets) as backend:
        with pytest.raises(RuntimeError, match="recovery required"):
            await rotate(
                settings,
                targets,
                passwords,
                CleanupFailure(),
                backend,
                directory=tmp_path / "retirement",
            )
    path = next((tmp_path / "retirement").glob("*.json"))
    record = json.loads(path.read_text())
    assert record["failed_phase"] == "retiring"
    for _ in range(140):
        save_journal(path, record)
    assert record["audit_offset"] >= 128 and len(record["events"]) <= 64
    assert load_journal(path, settings, "runtimes") == record
    archive = next((path.parent / "audit").glob("*.json"))
    original_archive = archive.read_bytes()
    archive.write_bytes(b"{}")
    corrupted_db = await database_password_fingerprint(settings)
    corrupted_labels = {
        t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        for t in targets
    }
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, client)
    assert await database_password_fingerprint(settings) == corrupted_db
    assert {
        t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        for t in targets
    } == corrupted_labels
    archive.write_bytes(original_archive)

    blocker = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with blocker.connect() as other:
            key = 0x435643524544454E
            await other.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key})
            await other.commit()
            locked_journal = path.read_bytes()
            with pytest.raises(RuntimeError, match="unavailable"):
                await recover(settings, path, client)
            assert path.read_bytes() == locked_journal
            assert await database_password_fingerprint(settings) == corrupted_db
            assert {
                t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
                for t in targets
            } == corrupted_labels
            await other.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            await other.commit()
    finally:
        await blocker.dispose()
    published_passwords = await database_password_fingerprint(settings)
    await recover(settings, path, client)
    assert await database_password_fingerprint(settings) == published_passwords
    record = json.loads(path.read_text())
    assert record["phase"] == "complete"
    for entry in record["entries"]:
        labels = client.describe_secret(SecretId=entry["target"]["secret_id"])["VersionIdsToStages"]
        assert "AWSCURRENT" in labels[entry["candidate_version"]]
        assert "AWSPENDING" not in labels[entry["candidate_version"]]
        assert "AWSPREVIOUS" in labels[entry["previous_version"]]
    before_repeat = path.read_bytes()
    await recover(settings, path, client)
    assert path.read_bytes() == before_repeat
    assert await database_password_fingerprint(settings) == published_passwords

    legacy = deepcopy(record)
    for field in ("events", "audit_offset", "audit_archive_sha256", "pending_retirement"):
        legacy.pop(field, None)
    legacy_path = tmp_path / "legacy-day14.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    for row in legacy["entries"]:
        client.update_secret_version_stage(
            SecretId=row["target"]["secret_id"],
            VersionStage="AWSPENDING",
            MoveToVersionId=row["candidate_version"],
        )
    await retire(settings, legacy_path, client)
    assert await database_password_fingerprint(settings) == published_passwords
    legacy_bytes = legacy_path.read_bytes()
    assert json.loads(legacy_bytes)["pending_retirement"] == "complete"
    await retire(settings, legacy_path, client)
    assert legacy_path.read_bytes() == legacy_bytes
    assert await database_password_fingerprint(settings) == published_passwords

    # Cancellation must hold the real management lock until a real cloud label request settles.
    started, release = threading.Event(), threading.Event()
    current_row = record["entries"][0]
    client.update_secret_version_stage(
        SecretId=current_row["target"]["secret_id"],
        VersionStage="DAY15_CANCEL_FIXTURE",
        MoveToVersionId=current_row["candidate_version"],
    )

    class SlowCloud:
        def update_secret_version_stage(self, **kwargs: Any) -> Any:
            started.set()
            assert release.wait(5)
            return client.update_secret_version_stage(**kwargs)

    async def cancelled_operation() -> None:
        async with password_manager(settings, targets):
            await request(
                SlowCloud(),
                "update_secret_version_stage",
                SecretId=current_row["target"]["secret_id"],
                VersionStage="DAY15_CANCEL_FIXTURE",
                RemoveFromVersionId=current_row["candidate_version"],
            )

    cancellation_engine = create_database_engine(bootstrap_database_settings(settings))
    task = asyncio.create_task(cancelled_operation())
    try:
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        async with cancellation_engine.connect() as other:
            key = 0x435643524544454E
            assert (
                await other.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}) is False
            )
            await other.commit()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert (
                await other.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}) is True
            )
            await other.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            await other.commit()
    finally:
        release.set()
        if not task.done():
            with suppress(asyncio.CancelledError):
                await task
        await cancellation_engine.dispose()
    assert (
        "DAY15_CANCEL_FIXTURE"
        not in client.describe_secret(SecretId=current_row["target"]["secret_id"])[
            "VersionIdsToStages"
        ][current_row["candidate_version"]]
    )
    # Prove the cluster management lock blocks a separate real PostgreSQL session.
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.connect() as other:
            major = int(await other.scalar(text("SHOW server_version_num"))) // 10000
            assert major == 16
            await other.commit()
            async with password_manager(settings, targets):
                assert (
                    await other.scalar(text("SELECT pg_try_advisory_lock(4852139669166769486)"))
                    is False
                )
                await other.commit()
            # Derive the actual constant here, and check release after context exit.
            key = 0x435643524544454E
            assert (
                await other.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}) is True
            )
            await other.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            await other.commit()
    finally:
        await engine.dispose()

    async def concurrent_rotation(number: int) -> Path:
        values = {t.role: f"day15-concurrent-{number}-" + t.role for t in targets}
        async with password_manager(settings, targets) as backend:
            return await rotate(
                settings,
                targets,
                values,
                client,
                backend,
                directory=tmp_path / f"concurrent-{number}",
            )

    paths = await asyncio.gather(concurrent_rotation(1), concurrent_rotation(2))
    records = [json.loads(p.read_text()) for p in paths]
    assert all(r["phase"] == "complete" for r in records)
    assert records[0]["operation_id"] != records[1]["operation_id"]
    assert any(
        all(
            new["previous_version"] == old["candidate_version"]
            for new, old in zip(later["entries"], earlier["entries"], strict=True)
        )
        for earlier, later in (records, records[::-1])
    )
    for t in targets:
        metadata = client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        assert sum("AWSCURRENT" in labels for labels in metadata.values()) == 1
        assert not any("AWSPENDING" in labels for labels in metadata.values())
    final_labels = deepcopy(
        {
            t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
            for t in targets
        }
    )
    # A completed old journal is idempotent and cannot undo a later operation.
    await recover(settings, path, client)
    assert {
        t.secret_id: client.describe_secret(SecretId=t.secret_id)["VersionIdsToStages"]
        for t in targets
    } == final_labels
    # Exercise rollback retirement against real unlabelled-version removal too.
    removals = 0
    rollback_passwords = {t.role: "day15-rollback-" + t.role for t in targets}
    async with password_manager(settings, targets) as backend:
        original_verify = backend.verify

        async def fail_candidate(target: Target, value: dict[str, Any]) -> None:
            if value["password"].startswith("day15-rollback-"):
                raise RuntimeError("injected candidate verification failure")
            await original_verify(target, value)

        monkeypatch.setattr(backend, "verify", fail_candidate)
        with pytest.raises(RuntimeError, match="recovery required"):
            await rotate(
                settings,
                targets,
                rollback_passwords,
                CleanupFailure(),
                backend,
                directory=tmp_path / "rollback-retirement",
            )
    rollback_path = next((tmp_path / "rollback-retirement").glob("*.json"))
    assert json.loads(rollback_path.read_text())["failed_phase"] == "recovery_verified"
    rolled_back_passwords = await database_password_fingerprint(settings)
    await recover(settings, rollback_path, client)
    assert await database_password_fingerprint(settings) == rolled_back_passwords
    assert json.loads(rollback_path.read_text())["phase"] == "recovered"
    assert all(
        not any(
            "AWSPENDING" in stages
            for stages in client.describe_secret(SecretId=t.secret_id)[
                "VersionIdsToStages"
            ].values()
        )
        for t in targets
    )
    for terminal in ("complete", "recovered"):
        directory = tmp_path / ("terminal-checkpoint-" + terminal)
        values = {t.role: "day15-final-" + terminal + "-" + t.role for t in targets}
        original_replace = os.replace
        failed = False

        def fail_terminal(
            source: Any,
            destination: Any,
            *,
            output_dir: Path = directory,
            terminal_stage: str = terminal,
            replace_file: Callable[[Any, Any], None] = original_replace,
        ) -> None:
            nonlocal failed
            if (
                Path(destination).parent == output_dir
                and not failed
                and json.loads(Path(source).read_text(encoding="utf-8"))["phase"] == terminal_stage
            ):
                failed = True
                raise OSError("injected terminal checkpoint failure")
            replace_file(source, destination)

        async with password_manager(settings, targets) as backend:
            original_verify = backend.verify

            async def fail_rollback_candidate(
                target: Target,
                value: dict[str, Any],
                *,
                terminal_stage: str = terminal,
                verify_login: Callable[[Target, dict[str, Any]], Awaitable[None]] = original_verify,
            ) -> None:
                if terminal_stage == "recovered" and value["password"].startswith(
                    "day15-final-recovered-"
                ):
                    raise RuntimeError("injected rollback trigger")
                await verify_login(target, value)

            with monkeypatch.context() as patch:
                patch.setattr("database.credential_audit.os.replace", fail_terminal)
                patch.setattr(backend, "verify", fail_rollback_candidate)
                with pytest.raises(RuntimeError, match="recovery required"):
                    await rotate(settings, targets, values, client, backend, directory=directory)
        terminal_path = next(directory.glob("*.json"))
        terminal_record = load_journal(terminal_path, settings, "runtimes")
        assert failed
        assert terminal_record["failed_phase"] == (
            "retiring" if terminal == "complete" else "recovery_verified"
        )
        if terminal == "recovered":
            assert terminal_record["recovery_failure_type"] == "OSError"
        terminal_passwords = await database_password_fingerprint(settings)
        await recover(settings, terminal_path, client)
        assert await database_password_fingerprint(settings) == terminal_passwords
        assert load_journal(terminal_path, settings, "runtimes")["phase"] == terminal
    evidence(
        "credential-lifecycle",
        {
            "terminal_checkpoint_failure_verified": True,
            "rollback_failure_metadata_verified": True,
            "lock_failure_no_side_effects": True,
            "legacy_terminal_retirement_verified": True,
            "audit_archive_verified": True,
            "cancelled_request_lock_verified": True,
            "scope": "localstack-and-postgresql",
            "postgres_major": 16,
            "foreign_pending_no_side_effects": True,
            "scheduled_deletion_no_side_effects": True,
            "partial_retirement_recovered": True,
            "rollback_retirement_recovered": True,
            "retirement_passwords_unchanged": True,
            "previous_version_retained": True,
            "pending_retired": True,
            "recovery_idempotent": True,
            "advisory_lock_verified": True,
            "concurrent_rotations_serialized": True,
            "old_completed_operation_isolated": True,
            "audit_secret_free": all(
                password not in path.read_text() for password in passwords.values()
            ),
            "iam_enforcement_verified": False,
        },
    )
