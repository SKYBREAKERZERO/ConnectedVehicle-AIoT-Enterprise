from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from database.credential_journal import CredentialPreflightError
from database.credential_rotation import Target, recover, rotate, save_journal
from enterprise_platform.config.settings import Settings
from tests.unit.test_credential_rotation import Passwords, candidates, setup, unfinished


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("pending_current", [False, True])
async def test_foreign_pending_cannot_be_overwritten(
    tmp_path: Path, existing: bool, pending_current: bool
) -> None:
    settings, targets, service, database = setup(existing)
    target = targets[2]
    version = service.put_secret_value(
        SecretId=target.secret_id,
        SecretString='{"password":"foreign"}',
        VersionStages=["AWSPENDING"],
    )["VersionId"]
    if pending_current:
        for labels in service.labels[target.secret_id].values():
            if "AWSCURRENT" in labels:
                labels.remove("AWSCURRENT")
        service.labels[target.secret_id][version].append("AWSCURRENT")
    before = deepcopy((service.values, service.labels, database.values, database.writes))
    service.calls.clear()
    with pytest.raises(CredentialPreflightError, match="Pending"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    assert (service.values, service.labels, database.values, database.writes) == before
    assert not service.calls.get("put_secret_value")
    assert not service.calls.get("update_secret_version_stage")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "case",
    [
        "deleted",
        "identity",
        "duplicate_pending",
        "duplicate_current",
        "duplicate_previous",
        "duplicate_label",
        "invalid_version",
    ],
)
async def test_resource_anomalies_reject_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    settings, targets, service, database = setup(True)
    original = service.describe_secret

    def invalid(**kwargs: Any) -> dict[str, Any]:
        result = deepcopy(original(**kwargs))
        if kwargs["SecretId"] != targets[2].secret_id:
            return result
        labels = result["VersionIdsToStages"]
        current = next(iter(labels))
        if case == "deleted":
            result["DeletedDate"] = "scheduled"
        elif case == "identity":
            result["Name"] = "/foreign"
        elif case.startswith("duplicate_") and case != "duplicate_label":
            stage = "AWS" + case.removeprefix("duplicate_").upper()
            labels[current].append(stage) if stage not in labels[current] else None
            labels[uuid4().hex] = [stage]
        elif case == "duplicate_label":
            labels[current].append("AWSCURRENT")
        else:
            labels["bad"] = ["CUSTOM"]
        return result

    monkeypatch.setattr(service, "describe_secret", invalid)
    before = deepcopy((service.values, service.labels, database.values, database.writes))
    with pytest.raises(CredentialPreflightError):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    assert (service.values, service.labels, database.values, database.writes) == before
    assert not list(tmp_path.iterdir()) and not service.calls.get("put_secret_value")


async def test_success_retires_only_own_pending_and_keeps_previous(tmp_path: Path) -> None:
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    assert [event["phase"] for event in record["events"]] == [
        "preparing",
        "prepared",
        "database_changed",
        "verified",
        "promoting",
        "retiring",
        "complete",
    ]
    assert [event["sequence"] for event in record["events"]] == list(range(1, 8))
    for entry in record["entries"]:
        labels = service.labels[entry["target"]["secret_id"]]
        assert labels[entry["candidate_version"]] == ["AWSCURRENT"]
        assert "AWSPREVIOUS" in labels[entry["previous_version"]]
    settings.credential_rotation_maintenance_mode = True
    second = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path / "second"
    )
    assert second != path


@pytest.mark.parametrize("rollback", [False, True])
async def test_partial_retirement_retry_does_not_rewrite_passwords(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rollback: bool
) -> None:
    settings, targets, service, database = setup(True)
    original = service.update_secret_version_stage
    removals = 0

    def fail_cleanup(**kwargs: Any) -> None:
        nonlocal removals
        if kwargs["VersionStage"] == "AWSPENDING":
            removals += 1
            if removals == 2:
                raise RuntimeError("private-cleanup-error")
        original(**kwargs)

    monkeypatch.setattr(service, "update_secret_version_stage", fail_cleanup)
    database.fail_verify = rollback
    with pytest.raises(RuntimeError, match="recovery required") as error:
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    assert "private" not in str(error.value)
    path = next(tmp_path.glob("*.json"))
    record = json.loads(path.read_text())
    assert record["failed_phase"] == ("recovery_verified" if rollback else "retiring")
    writes = database.writes
    database.fail_verify = False

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    await recover(settings, path, service)
    assert database.writes == writes
    assert json.loads(path.read_text())["phase"] == ("recovered" if rollback else "complete")
    assert all(
        "AWSPENDING" not in labels for rows in service.labels.values() for labels in rows.values()
    )
    before = deepcopy((service.values, service.labels, database.values, path.read_bytes()))
    await recover(settings, path, service)
    assert (service.values, service.labels, database.values, path.read_bytes()) == before


async def test_foreign_pending_blocks_old_recovery_without_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database, path = await unfinished(tmp_path)
    service.put_secret_value(
        SecretId=targets[2].secret_id,
        SecretString='{"password":"foreign"}',
        VersionStages=["AWSPENDING"],
    )
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before


async def test_unfinished_operation_blocks_new_rotation(tmp_path: Path) -> None:
    settings, targets, service, database, path = await unfinished(tmp_path)
    before = deepcopy((service.values, service.labels, database.values, path.read_bytes()))
    with pytest.raises(CredentialPreflightError, match="Pending"):
        await rotate(
            settings, targets, candidates(targets), service, database, directory=tmp_path / "new"
        )
    assert (service.values, service.labels, database.values, path.read_bytes()) == before
    assert not (tmp_path / "new").exists()


async def test_illegal_state_transition_cannot_be_persisted(tmp_path: Path) -> None:
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    before = path.read_bytes()
    record = json.loads(before)
    record["phase"] = "prepared"
    with pytest.raises(ValueError, match="Illegal"):
        save_journal(path, record)
    assert path.read_bytes() == before


async def test_retirement_verification_failure_keeps_forward_recovery_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    service.fail_method, service.fail_call = "update_secret_version_stage", 5
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))
    writes = database.writes

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    database.fail_verify = True
    audit_before = len(json.loads(path.read_text())["events"])
    with pytest.raises(RuntimeError, match="recovery required"):
        await recover(settings, path, service)
    assert len(json.loads(path.read_text())["events"]) == audit_before + 1
    assert json.loads(path.read_text())["failed_phase"] == "retiring"
    database.fail_verify = False
    await recover(settings, path, service)
    assert database.writes == writes
    assert json.loads(path.read_text())["phase"] == "complete"
