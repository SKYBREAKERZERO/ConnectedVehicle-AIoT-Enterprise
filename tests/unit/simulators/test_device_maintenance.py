from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from connected_vehicle.remote_command.domain import RemoteCommandType
from simulators.body_ecu.service import BodyStore
from simulators.gateway.service import GatewayStore
from simulators.vehicle_device.can import command_frame
from simulators.vehicle_device.maintenance import snapshot
from simulators.vehicle_device.ownership import RuntimeAlreadyRunningError, runtime_lock
from simulators.vehicle_device.store import Store
from tests.unit.test_device_simulator import payload, settings


def test_online_snapshot_preserves_wal_identity_and_outbox(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.accept(command)
    store.finish(str(command.command_id))
    original = [tuple(row) for row in store.db.execute("SELECT * FROM reports")]
    backup = tmp_path / "snapshot.sqlite"
    restored = tmp_path / "restored.sqlite"
    try:
        assert Path(str(config.database) + "-wal").is_file()
        with runtime_lock(config.database):
            assert snapshot(config.database, backup)["integrity"] == "ok"
        snapshot(backup, restored)
        recovered = Store(restored)
        try:
            with pytest.raises(ValueError, match="identity_mismatch"):
                recovered.bind_identity("tenant-b", str(config.vehicle_id))
            recovered.bind_identity(config.tenant_id, str(config.vehicle_id))
            assert not recovered.accept(command)
            assert [tuple(row) for row in recovered.db.execute("SELECT * FROM reports")] == original
            assert recovered.db.execute("SELECT can_version FROM commands").fetchone()[0] == 2
        finally:
            recovered.close()
    finally:
        store.close()


def test_restored_ecu_keeps_execution_dedup_and_state(tmp_path: Path) -> None:
    source = tmp_path / "body.sqlite"
    body = BodyStore(source)
    frame = command_frame(uuid4(), 1, 2**32 - 1)
    body.execute(frame)
    try:
        snapshot(source, tmp_path / "restored.sqlite")
        recovered = BodyStore(tmp_path / "restored.sqlite")
        try:
            assert recovered.execute(frame).data == b"\x00"
            assert recovered.reconcile()["count"] == 1
            assert recovered.reconcile()["locked"] is True
        finally:
            recovered.close()
    finally:
        body.close()


def test_gateway_pending_routes_survive_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "gateway.sqlite"
    gateway = GatewayStore(source)
    frame = command_frame(uuid4(), 1, 2**32 - 1)
    gateway.accept(frame)
    try:
        snapshot(source, tmp_path / "restored.sqlite")
        recovered = GatewayStore(tmp_path / "restored.sqlite")
        try:
            assert recovered.pending() == [frame]
        finally:
            recovered.close()
    finally:
        gateway.close()


def test_snapshot_never_overwrites_or_creates_missing_source(tmp_path: Path) -> None:
    source = tmp_path / "device.sqlite"
    store = Store(source)
    store.close()
    target = tmp_path / "keep.sqlite"
    target.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        snapshot(source, target)
    assert target.read_bytes() == b"keep me"
    with pytest.raises(FileNotFoundError):
        snapshot(tmp_path / "missing.sqlite", tmp_path / "new.sqlite")
    assert not (tmp_path / "missing.sqlite").exists()
    with pytest.raises(ValueError, match="equals"):
        snapshot(source, source)


def test_failed_snapshot_is_not_published(tmp_path: Path) -> None:
    source = tmp_path / "foreign.sqlite"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE foreign_data(id INTEGER)")
    with pytest.raises(ValueError, match="unsupported"):
        snapshot(source, tmp_path / "snapshot.sqlite")
    assert not (tmp_path / "snapshot.sqlite").exists()
    assert not list(tmp_path.glob(".device-backup-*"))


def test_snapshot_target_requires_exclusive_owner(tmp_path: Path) -> None:
    source = tmp_path / "device.sqlite"
    store = Store(source)
    store.close()
    target = tmp_path / "new.sqlite"
    with runtime_lock(target), pytest.raises(RuntimeAlreadyRunningError):
        snapshot(source, target)
    assert not target.exists()


@pytest.mark.parametrize("role", ["tbox", "body", "gateway"])
def test_failed_database_initialization_closes_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    connection = Mock()
    connection.execute.side_effect = sqlite3.DatabaseError("not a database")
    monkeypatch.setattr(sqlite3, "connect", lambda path: connection)
    constructor = {"tbox": Store, "body": BodyStore, "gateway": GatewayStore}[role]
    with pytest.raises(sqlite3.DatabaseError):
        constructor(tmp_path / "device.sqlite")
    connection.close.assert_called_once()


def test_timeout_keeps_destination_unpublished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "device.sqlite"
    store = Store(source)
    store.close()
    clock = iter([0.0, 31.0])
    monkeypatch.setattr("simulators.vehicle_device.maintenance.monotonic", lambda: next(clock))
    with pytest.raises(TimeoutError):
        snapshot(source, tmp_path / "snapshot.sqlite")
    assert not (tmp_path / "snapshot.sqlite").exists()
    assert not list(tmp_path.glob(".device-backup-*"))


def test_bound_ledger_rejects_foreign_commands_without_explicit_rebind(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.close()
    recovered = Store(config.database)
    try:
        with pytest.raises(ValueError, match="identity_mismatch"):
            recovered.accept(payload(config).model_copy(update={"tenant_id": "tenant-b"}))
        with pytest.raises(ValueError, match="identity_mismatch"):
            recovered.accept(payload(config).model_copy(update={"vehicle_id": uuid4()}))
        assert recovered.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 0
        assert recovered.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    finally:
        recovered.close()


def test_corrupt_disk_is_rejected_and_verified_backup_recovers(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.accept(command)
    store.close()
    backup = tmp_path / "backup.sqlite"
    snapshot(config.database, backup)
    config.database.write_bytes(b"corrupted disk header" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        Store(config.database)
    with pytest.raises(sqlite3.DatabaseError):
        snapshot(config.database, tmp_path / "invalid.sqlite")
    assert not (tmp_path / "invalid.sqlite").exists()
    snapshot(backup, tmp_path / "recovered.sqlite")
    recovered = Store(tmp_path / "recovered.sqlite")
    try:
        recovered.bind_identity(config.tenant_id, str(config.vehicle_id))
        assert not recovered.accept(command)
        report = recovered.pending_report()
        assert report is not None and report["command_id"] == str(command.command_id)
    finally:
        recovered.close()


def test_archive_keeps_dedup_and_unfinished_reports(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    from simulators.vehicle_device.maintenance import archive

    config = settings(tmp_path)
    command = payload(config).model_copy(
        update={
            "created_at": datetime.now(UTC) - timedelta(days=3),
            "expires_at": datetime.now(UTC) - timedelta(days=2),
        }
    )
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.accept(command)
    store.finish(str(command.command_id))
    assert (
        archive(
            config.database,
            tmp_path / "unfinished.sqlite",
            before=datetime.now(UTC) - timedelta(days=1),
        )["archived_commands"]
        == 0
    )
    ack = store.pending_report()
    assert ack is not None
    store.report_result(ack["sequence"], 401, 7)
    replay = dict(
        event_id=json.loads(ack["payload"])["event_id"],
        operation_id=str(uuid4()),
        actor="operator",
        reason="repaired credentials",
        tenant_id=config.tenant_id,
        vehicle_id=str(config.vehicle_id),
    )
    assert store.requeue_report(**replay)
    audit = [tuple(row) for row in store.db.execute("SELECT * FROM report_replays")]
    for row in store.db.execute("SELECT sequence FROM reports").fetchall():
        store.report_result(row[0], 200, 0)
    store.close()
    assert (
        archive(
            config.database,
            tmp_path / "completed.sqlite",
            before=datetime.now(UTC) - timedelta(days=1),
        )["archived_commands"]
        == 1
    )
    recovered = Store(config.database)
    try:
        assert not recovered.accept(command)
        assert [tuple(row) for row in recovered.db.execute("SELECT * FROM report_replays")] == audit
        assert not recovered.requeue_report(**replay)
        assert recovered.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
        with pytest.raises(ValueError, match="conflict"):
            recovered.accept(command.model_copy(update={"command_type": RemoteCommandType.UNLOCK}))
    finally:
        recovered.close()


def test_online_archive_uses_snapshot_candidates_and_keeps_new_live_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime, timedelta

    from simulators.vehicle_device.maintenance import archive

    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    old = payload(config).model_copy(
        update={
            "created_at": datetime.now(UTC) - timedelta(days=3),
            "expires_at": datetime.now(UTC) - timedelta(days=2),
        }
    )
    store.accept(old)
    store.finish(str(old.command_id))
    for row in store.db.execute("SELECT sequence FROM reports").fetchall():
        store.report_result(row[0], 200, 0)
    newer = payload(config)
    original = snapshot

    def race(source: Path, destination: Path) -> dict[str, object]:
        result = original(source, destination)
        store.accept(newer)
        return result

    monkeypatch.setattr("simulators.vehicle_device.maintenance.snapshot", race)
    try:
        with runtime_lock(config.database):
            result = archive(
                config.database,
                tmp_path / "online.sqlite",
                before=datetime.now(UTC) - timedelta(days=1),
                online=True,
            )
        assert result["archived_commands"] == 1
        assert not store.accept(old)
        pending = store.pending_command()
        assert pending is not None and pending["id"] == str(newer.command_id)
        report = store.pending_report()
        assert report is not None and report["command_id"] == str(newer.command_id)
    finally:
        store.close()
