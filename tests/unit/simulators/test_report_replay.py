from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from simulators.vehicle_device.store import Store
from tests.unit.test_device_simulator import payload, settings


def test_scoped_replay_is_audited_idempotent_and_preserves_payload(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    try:
        for _ in range(2):
            store.accept(payload(config))
        rows = store.db.execute("SELECT * FROM reports").fetchall()
        for row in rows:
            store.report_result(row["sequence"], 409, 0)
        event = json.loads(rows[0]["payload"])["event_id"]
        operation = str(uuid4())
        metadata = {
            "tenant_id": config.tenant_id,
            "vehicle_id": str(config.vehicle_id),
            "event_id": event,
            "operation_id": operation,
            "actor": "operator-1",
            "reason": "Cloud conflict reconciled",
        }
        assert store.requeue_report(**metadata)
        assert not store.requeue_report(**metadata)
        after = store.db.execute("SELECT * FROM reports ORDER BY sequence").fetchall()
        assert [row["state"] for row in after] == ["pending", "blocked"]
        assert [row["payload"] for row in after] == [row["payload"] for row in rows]
        assert store.db.execute("SELECT count(*) FROM report_replays").fetchone()[0] == 1
        audit = store.db.execute("SELECT * FROM report_replays").fetchone()
        assert audit["previous_error"] == "409"
        with pytest.raises(ValueError, match="conflict"):
            store.requeue_report(**(metadata | {"actor": "operator-2"}))
    finally:
        store.close()
    recovered = Store(config.database)
    try:
        assert not recovered.requeue_report(**metadata)
    finally:
        recovered.close()


@pytest.mark.parametrize("actor,reason", [("", "incident"), ("operator", ""), ("op\n", "incident")])
def test_replay_invalid_metadata_changes_nothing(tmp_path: Path, actor: str, reason: str) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    try:
        store.accept(payload(config))
        row = store.pending_report()
        assert row is not None
        store.report_result(row["sequence"], 409, 0)
        with pytest.raises(ValueError):
            store.requeue_report(
                tenant_id=config.tenant_id,
                vehicle_id=str(config.vehicle_id),
                event_id=json.loads(row["payload"])["event_id"],
                operation_id=str(uuid4()),
                actor=actor,
                reason=reason,
            )
        assert store.db.execute("SELECT state FROM reports").fetchone()[0] == "blocked"
        assert store.db.execute("SELECT count(*) FROM report_replays").fetchone()[0] == 0
    finally:
        store.close()


def test_bulk_replay_disabled(tmp_path: Path) -> None:
    store = Store(tmp_path / "device.sqlite")
    try:
        with pytest.raises(ValueError, match="bulk_replay_disabled"):
            store.reconcile(requeue=True)
    finally:
        store.close()


def test_pending_report_cannot_be_replayed(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    try:
        store.accept(payload(config))
        row = store.pending_report()
        assert row is not None
        with pytest.raises(ValueError, match="requires_blocked"):
            store.requeue_report(
                tenant_id=config.tenant_id,
                vehicle_id=str(config.vehicle_id),
                event_id=json.loads(row["payload"])["event_id"],
                operation_id=str(uuid4()),
                actor="op",
                reason="incident",
            )
        assert store.db.execute("SELECT count(*) FROM report_replays").fetchone()[0] == 0
    finally:
        store.close()
