from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from simulators.vehicle_device.maintenance import RestoreAudit, digest, snapshot
from simulators.vehicle_device.store import Store
from tests.integration.day12.conftest import evidence
from tests.unit.test_device_simulator import payload, settings


def test_verified_restore_preserves_replay_audit_dedup_and_ack_order(tmp_path: Path) -> None:
    config = settings(tmp_path)
    command = payload(config)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.accept(command)
    store.finish(str(command.command_id))
    ack = store.pending_report()
    assert ack is not None
    store.report_result(ack["sequence"], 401, 7)
    operation_id = str(uuid4())
    replay = dict(
        event_id=json.loads(ack["payload"])["event_id"],
        operation_id=operation_id,
        actor="local-operator",
        reason="local token repaired",
        tenant_id=config.tenant_id,
        vehicle_id=str(config.vehicle_id),
    )
    assert store.requeue_report(**replay)
    original = [tuple(row) for row in store.db.execute("SELECT * FROM reports")]
    store.close()
    backup = tmp_path / "backup.sqlite"
    sha = str(snapshot(config.database, backup)["sha256"])
    target = tmp_path / "restored.sqlite"
    restore_id = str(uuid4())
    snapshot(
        backup,
        target,
        expected_sha256=sha,
        restore_audit=RestoreAudit(
            operation_id=restore_id,
            actor="local-operator",
            reason="verified disaster recovery exercise",
        ),
    )
    recovered = Store(target)
    try:
        recovered.bind_identity(config.tenant_id, str(config.vehicle_id))
        assert not recovered.accept(command)
        assert [tuple(row) for row in recovered.db.execute("SELECT * FROM reports")] == original
        assert not recovered.requeue_report(**replay)
        assert recovered.db.execute("SELECT count(*) FROM report_replays").fetchone()[0] == 1
        restored_audit = recovered.db.execute("SELECT * FROM maintenance_audit").fetchone()
        assert restored_audit["operation_id"] == restore_id
        assert restored_audit["source_sha256"] == sha
        pending = recovered.pending_report()
        assert pending is not None and pending["sequence"] == ack["sequence"]
        recovered.report_result(ack["sequence"], 200, 0)
        terminal = recovered.pending_report()
        assert terminal is not None and terminal["sequence"] > ack["sequence"]
    finally:
        recovered.close()
    evidence(
        "12d-restore",
        {
            "sha256_verified": True,
            "identity_preserved": True,
            "dedup_preserved": True,
            "ack_order_preserved": True,
            "event_and_restore_audit": "passed",
        },
    )


def test_logically_valid_backup_tampering_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    Store(source).close()
    backup = tmp_path / "backup.sqlite"
    sha = str(snapshot(source, backup)["sha256"])
    with sqlite3.connect(backup) as connection:
        connection.execute("INSERT INTO faults VALUES ('tampered')")
    connection.close()
    assert digest(backup) != sha
    with pytest.raises(ValueError, match="digest_mismatch"):
        snapshot(backup, tmp_path / "restore.sqlite", expected_sha256=sha)
    assert not (tmp_path / "restore.sqlite").exists()


def test_invalid_restore_audit_does_not_publish(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    Store(source).close()
    backup = tmp_path / "backup.sqlite"
    sha = str(snapshot(source, backup)["sha256"])
    with pytest.raises(ValueError, match="metadata_required"):
        snapshot(
            backup,
            tmp_path / "restore.sqlite",
            expected_sha256=sha,
            restore_audit=RestoreAudit(operation_id=str(uuid4()), actor="", reason="restore"),
        )
    assert not (tmp_path / "restore.sqlite").exists()


def test_restore_audit_failure_keeps_destination_unpublished(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    Store(source).close()
    operation_id = str(uuid4())
    with sqlite3.connect(source) as connection:
        connection.execute("""CREATE TABLE maintenance_audit (
            operation_id TEXT PRIMARY KEY, actor TEXT, reason TEXT, source_sha256 TEXT,
            created_at TEXT)""")
        connection.execute(
            "INSERT INTO maintenance_audit VALUES (?,?,?,?,?)",
            (operation_id, "operator", "previous restore", "prior-digest", "prior-time"),
        )
    connection.close()
    backup = tmp_path / "backup.sqlite"
    sha = str(snapshot(source, backup)["sha256"])
    with pytest.raises(sqlite3.IntegrityError):
        snapshot(
            backup,
            tmp_path / "restore.sqlite",
            expected_sha256=sha,
            restore_audit=RestoreAudit(
                operation_id=operation_id, actor="operator", reason="restore"
            ),
        )
    assert not (tmp_path / "restore.sqlite").exists()
    assert not list(tmp_path.glob(".device-backup-*"))
    assert digest(backup) == sha
