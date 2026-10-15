from __future__ import annotations

import asyncio
import json
import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from database.credential_journal import CredentialPreflightError, load_journal
from database.credential_rotation import Target, recover, request, retire, rotate, save_journal
from enterprise_platform.config.settings import Settings
from tests.unit.test_credential_rotation import Passwords, candidates, setup, unfinished


def manager_for(database: Passwords) -> Any:
    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    return manager


async def terminal_fixture(tmp_path: Path, outcome: str = "complete") -> tuple[Any, ...]:
    settings, targets, service, database = setup(True)
    if outcome == "recovered":
        database.fail_verify = True
        with pytest.raises(RuntimeError, match="was recovered"):
            await rotate(
                settings, targets, candidates(targets), service, database, directory=tmp_path
            )
        database.fail_verify = False
        path = next(tmp_path.glob("*.json"))
    else:
        path = await rotate(
            settings, targets, candidates(targets), service, database, directory=tmp_path
        )
    record = json.loads(path.read_text())
    # Day14 terminal v2 logs predate lifecycle events and automatic Pending retirement.
    record.pop("events")
    path.write_text(json.dumps(record), encoding="utf-8")
    for row in record["entries"]:
        service.labels[row["target"]["secret_id"]][row["candidate_version"]].append("AWSPENDING")
    return settings, targets, service, database, path


async def test_lock_acquisition_failure_does_not_rewrite_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    before = deepcopy((service.values, service.labels, database.values, path.read_bytes()))

    @asynccontextmanager
    async def unavailable(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        if settings.database_host:
            raise RuntimeError("private-bootstrap-or-lock-failure")
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", unavailable)
    with pytest.raises(RuntimeError, match="unavailable") as error:
        await recover(settings, path, service)
    assert "private" not in str(error.value)
    assert (service.values, service.labels, database.values, path.read_bytes()) == before
    assert not service.calls


async def test_cancellation_waits_for_remote_mutation_before_releasing_lock() -> None:
    started, release = threading.Event(), threading.Event()
    events: list[str] = []
    lock = asyncio.Lock()

    class SlowClient:
        def mutate(self) -> None:
            events.append("started")
            started.set()
            assert release.wait(5)
            events.append("finished")

    async def operation() -> None:
        async with lock:
            try:
                await request(SlowClient(), "mutate")
            finally:
                events.append("released")

    task = asyncio.create_task(operation())
    try:
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert lock.locked() and not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert events == ["started", "finished", "released"]
    assert not lock.locked()


async def test_over_128_audit_events_are_preserved_and_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    service.fail_method, service.fail_call = "update_secret_version_stage", 5
    with pytest.raises(RuntimeError):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))
    record = json.loads(path.read_text())
    for _ in range(140):
        save_journal(path, record)
    assert record["audit_offset"] >= 128 and len(record["events"]) <= 64
    assert len(list((tmp_path / "audit").glob("*.json"))) >= 2
    assert load_journal(path, settings, "runtimes") == record
    writes = database.writes
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    await recover(settings, path, service)
    assert database.writes == writes
    result = load_journal(path, settings, "runtimes")
    assert result["phase"] == "complete"
    assert result["events"][-1]["sequence"] > 140


@pytest.mark.parametrize("case", ["tampered", "missing", "wrong_sequence", "illegal_transition"])
async def test_bad_audit_records_reject_before_connecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    record = json.loads(path.read_text())
    for _ in range(70):
        save_journal(path, record)
    if case in {"tampered", "missing"}:
        archive = next((tmp_path / "audit").glob("*.json"))
        if case == "tampered":
            archive.write_bytes(b"{}")
        else:
            archive.unlink()
    elif case == "wrong_sequence":
        record["events"][0]["sequence"] = 1
        path.write_text(json.dumps(record), encoding="utf-8")
    else:
        record["events"][0]["phase"] = "complete"
        path.write_text(json.dumps(record), encoding="utf-8")
    before = deepcopy((service.values, service.labels, database.values, path.read_bytes()))
    connections = 0

    @asynccontextmanager
    async def forbidden(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        nonlocal connections
        connections += 1
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", forbidden)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert connections == 0
    assert (service.values, service.labels, database.values, path.read_bytes()) == before
    assert not service.calls


async def test_failed_checkpoint_write_does_not_advance_in_memory_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    before, raw = deepcopy(record), path.read_bytes()

    def fail(*args: Any) -> None:
        raise OSError("injected journal publication failure")

    monkeypatch.setattr("database.credential_audit.os.replace", fail)
    with pytest.raises(OSError):
        save_journal(path, record)
    assert record == before and path.read_bytes() == raw
    assert list(tmp_path.glob("*.json")) == [path]


@pytest.mark.parametrize("outcome", ["complete", "recovered"])
async def test_legacy_terminal_pending_retirement_is_explicit_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    settings, _, service, database, path = await terminal_fixture(tmp_path, outcome)
    writes = database.writes
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    await retire(settings, path, service)
    record = json.loads(path.read_text())
    assert record["phase"] == outcome and record["pending_retirement"] == "complete"
    assert database.writes == writes
    assert all(
        "AWSPENDING" not in stages for rows in service.labels.values() for stages in rows.values()
    )
    assert [row["action"] for row in record["events"]] == ["retire_pending"] * 2
    before = deepcopy((service.values, service.labels, database.values, path.read_bytes()))
    await retire(settings, path, service)
    assert (service.values, service.labels, database.values, path.read_bytes()) == before


async def test_legacy_retirement_failure_and_retry_never_write_passwords(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _, service, database, path = await terminal_fixture(tmp_path)
    writes = database.writes
    service.calls.clear()
    service.fail_method, service.fail_call = "update_secret_version_stage", 2
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    with pytest.raises(RuntimeError, match="retry required"):
        await retire(settings, path, service)
    assert json.loads(path.read_text())["pending_retirement"] == "retry_required"
    with pytest.raises(CredentialPreflightError, match="--retire"):
        await recover(settings, path, service)
    await retire(settings, path, service)
    assert database.writes == writes
    assert json.loads(path.read_text())["pending_retirement"] == "complete"


@pytest.mark.parametrize(
    "case", ["foreign_pending", "later_current", "verification_failure", "unfinished"]
)
async def test_legacy_retirement_invalid_target_does_not_change_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    settings, targets, service, database, path = await terminal_fixture(tmp_path)
    target = targets[-1]
    if case == "foreign_pending":
        service.put_secret_value(
            SecretId=target.secret_id,
            SecretString='{"password":"foreign"}',
            VersionStages=["AWSPENDING"],
        )
    elif case == "later_current":
        service.put_secret_value(SecretId=target.secret_id, SecretString='{"password":"foreign"}')
    elif case == "verification_failure":
        database.fail_verify = True
    else:
        record = json.loads(path.read_text())
        record["phase"] = "prepared"
        path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )
    with pytest.raises((CredentialPreflightError, RuntimeError)):
        await retire(settings, path, service)
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before


async def test_pending_takeover_after_prepare_cannot_change_database_passwords(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    original = service.put_secret_value
    foreign_version: str | None = None

    def takeover(**kwargs: Any) -> dict[str, str]:
        nonlocal foreign_version
        result = original(**kwargs)
        if kwargs["SecretId"] == targets[-1].secret_id:
            foreign_version = original(
                SecretId=targets[0].secret_id,
                SecretString='{"password":"foreign"}',
                VersionStages=["AWSPENDING"],
            )["VersionId"]
        return result

    monkeypatch.setattr(service, "put_secret_value", takeover)
    before = deepcopy(database.values)
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    assert database.writes == 0 and database.values == before
    assert foreign_version is not None
    assert service.labels[targets[0].secret_id][foreign_version] == ["AWSPENDING"]


async def test_last_retirement_check_catches_late_current_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    original = service.update_secret_version_stage
    later = uuid4().hex

    def changed(**kwargs: Any) -> None:
        original(**kwargs)
        if kwargs["SecretId"] == targets[-1].secret_id and kwargs["VersionStage"] == "AWSPENDING":
            service.put_secret_value(
                SecretId=targets[0].secret_id,
                SecretString='{"password":"foreign"}',
                ClientRequestToken=later,
            )

    monkeypatch.setattr(service, "update_secret_version_stage", changed)
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    record = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert record["phase"] == "recovery_required" and record["failed_phase"] == "retiring"
    assert "AWSCURRENT" in service.labels[targets[0].secret_id][later]


async def test_recovery_retirement_rechecks_file_after_login_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    database.fail_verify = True
    service.fail_method, service.fail_call = "update_secret_version_stage", 2
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))
    assert json.loads(path.read_text())["failed_phase"] == "recovery_verified"
    database.fail_verify = False
    original = database.verify
    replacement: bytes | None = None

    async def replaced(target: Target, value: dict[str, Any]) -> None:
        nonlocal replacement
        await original(target, value)
        if replacement is None:
            record = json.loads(path.read_text())
            record["database"]["host"] = "attacker.invalid"
            replacement = json.dumps(record).encode("utf-8")
            path.write_bytes(replacement)

    monkeypatch.setattr(database, "verify", replaced)
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    before = deepcopy((service.values, service.labels, database.values, database.writes))
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert (service.values, service.labels, database.values, database.writes) == before
    assert path.read_bytes() == replacement


def test_recovery_and_retirement_cli_modes_are_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from database import provision_runtime_credentials as command

    called: list[bool] = []

    def settings() -> Settings:
        called.append(True)
        return Settings.model_construct()

    monkeypatch.setattr(command, "Settings", settings)
    monkeypatch.setattr("sys.argv", ["provision", "--recover", "a.json", "--retire", "b.json"])
    with pytest.raises(SystemExit) as error:
        command.main()
    assert error.value.code == 2 and not called


@pytest.mark.parametrize("terminal", ["complete", "recovered"])
async def test_terminal_checkpoint_failure_keeps_correct_recovery_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal: str
) -> None:

    settings, targets, service, database = setup(True)
    database.fail_verify = terminal == "recovered"
    original = os.replace
    failures = 0

    def fail_once(source: Any, destination: Any) -> None:
        nonlocal failures
        if json.loads(Path(source).read_text())["phase"] == terminal and failures == 0:
            failures += 1
            raise OSError("private-terminal-checkpoint-failure")
        original(source, destination)

    monkeypatch.setattr("database.credential_audit.os.replace", fail_once)
    with pytest.raises(RuntimeError, match="recovery required") as error:
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    assert "private" not in str(error.value)
    path = next(tmp_path.glob("*.json"))
    record = load_journal(path, settings, "runtimes")
    assert record["failed_phase"] == ("retiring" if terminal == "complete" else "recovery_verified")
    if terminal == "recovered":
        assert record["recovery_failure_type"] == "OSError"
    writes = database.writes
    database.fail_verify = False
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    await recover(settings, path, service)
    assert database.writes == writes
    assert load_journal(path, settings, "runtimes")["phase"] == terminal


async def test_invalid_checkpoint_does_not_publish_archive_at_boundary(tmp_path: Path) -> None:
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    while len(record["events"]) < 64:
        save_journal(path, record)
    raw = path.read_bytes()
    record["failure_type"], record["failed_phase"] = "RuntimeError", "complete"
    before = deepcopy(record)
    with pytest.raises(ValueError):
        save_journal(path, record)
    assert record == before and path.read_bytes() == raw
    assert not (tmp_path / "audit").exists()


async def test_archive_capacity_rejection_preserves_a_readable_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("database.credential_audit.MAX_ARCHIVES", 1)
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    while record.get("audit_offset", 0) + len(record["events"]) < 128:
        save_journal(path, record)
    before, raw = deepcopy(record), path.read_bytes()
    with pytest.raises(ValueError, match="capacity"):
        save_journal(path, record)
    assert record == before and path.read_bytes() == raw
    assert len(list((tmp_path / "audit").glob("*.json"))) == 1
    assert load_journal(path, settings, "runtimes") == before


async def test_database_password_drift_during_retirement_cannot_publish_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, targets, service, database = setup(True)
    original = service.update_secret_version_stage

    def drift(**kwargs: Any) -> None:
        original(**kwargs)
        if kwargs["SecretId"] == targets[-1].secret_id and kwargs["VersionStage"] == "AWSPENDING":
            database.values[targets[0].role] = "external-password-change"

    monkeypatch.setattr(service, "update_secret_version_stage", drift)
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), service, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))
    record = load_journal(path, settings, "runtimes")
    assert record["phase"] == "recovery_required" and record["failed_phase"] == "retiring"
    assert database.values[targets[0].role] == "external-password-change"


async def test_nullable_legacy_failure_metadata_can_record_a_new_recovery_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    record = json.loads(path.read_text())
    record.pop("events")
    record["phase"] = "prepared"
    record["failure_type"] = record["failed_phase"] = record["recovery_failure_type"] = None
    path.write_text(json.dumps(record), encoding="utf-8")
    database.fail_restore = True
    monkeypatch.setattr("database.credential_rotation.password_manager", manager_for(database))
    with pytest.raises(RuntimeError, match="recovery required"):
        await recover(settings, path, service)
    failed = load_journal(path, settings, "runtimes")
    assert failed["phase"] == "recovery_required" and failed["failure_type"] == "RuntimeError"
    assert failed["recovery_failure_type"] == "RuntimeError"
    database.fail_restore = False
    await recover(settings, path, service)
    assert load_journal(path, settings, "runtimes")["phase"] == "recovered"
