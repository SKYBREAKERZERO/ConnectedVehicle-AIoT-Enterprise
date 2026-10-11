from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

from simulators.vehicle_device.store import Store
from tests.unit.test_device_simulator import payload, settings


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[tuple[Store, dict[str, str]]]:
    config = settings(tmp_path)
    with_store = Store(config.database)
    with_store.bind_identity(config.tenant_id, str(config.vehicle_id))
    for _ in range(3):
        with_store.accept(payload(config))
    for row in with_store.db.execute("SELECT * FROM reports").fetchall():
        with_store.report_result(row["sequence"], 409, 2)
    event = json.loads(str(reports(with_store)[0]["payload"]))["event_id"]
    metadata = dict(
        event_id=event,
        operation_id=str(uuid4()),
        actor="operator",
        reason="incident reconciled",
        tenant_id=config.tenant_id,
        vehicle_id=str(config.vehicle_id),
    )
    try:
        yield with_store, metadata
    finally:
        with_store.close()


def reports(store: Store) -> list[dict[str, object]]:
    return [dict(row) for row in store.db.execute("SELECT * FROM reports ORDER BY sequence")]


def snapshot(store: Store) -> dict[str, list[tuple[object, ...]]]:
    return {
        table: [tuple(row) for row in store.db.execute(f"SELECT * FROM {table} ORDER BY rowid")]
        for table in (
            "commands",
            "reports",
            "report_replays",
            "device_identity",
            "quarantine",
            "faults",
            "sqlite_sequence",
        )
    }


def test_01_only_selected_event_changes(ledger: tuple[Store, dict[str, str]]) -> None:
    store, metadata = ledger
    before = reports(store)
    assert store.requeue_report(**metadata)
    after = reports(store)
    assert after[0] == before[0] | {"state": "pending", "next_attempt": 0.0}
    assert after[1:] == before[1:]


def test_02_unselected_complete_records_unchanged(ledger: tuple[Store, dict[str, str]]) -> None:
    store, metadata = ledger
    before = snapshot(store)
    store.requeue_report(**metadata)
    after = snapshot(store)
    assert before["reports"][1:] == after["reports"][1:]
    for table in ("commands", "device_identity", "quarantine", "faults", "sqlite_sequence"):
        assert before[table] == after[table]


def test_03_original_payload_and_sha256_unchanged(ledger: tuple[Store, dict[str, str]]) -> None:
    store, metadata = ledger

    def digests() -> list[tuple[str, str]]:
        return [
            (str(row["payload"]), hashlib.sha256(str(row["payload"]).encode()).hexdigest())
            for row in reports(store)
        ]

    before = digests()
    store.requeue_report(**metadata)
    assert digests() == before


@pytest.mark.parametrize("field", ["operation_id", "actor", "reason"])
def test_04_05_06_missing_metadata_no_database_change(
    ledger: tuple[Store, dict[str, str]],
    field: str,
) -> None:
    store, metadata = ledger
    before = snapshot(store)
    with pytest.raises(ValueError):
        store.requeue_report(**(metadata | {field: ""}))
    assert snapshot(store) == before
    omitted = metadata.copy()
    del omitted[field]
    with pytest.raises(TypeError):
        store.requeue_report(**omitted)
    assert snapshot(store) == before


def test_07_duplicate_updates_once_and_audits_once(ledger: tuple[Store, dict[str, str]]) -> None:
    store, metadata = ledger
    store.requeue_report(**metadata)
    before, changes = snapshot(store), store.db.total_changes
    assert not store.requeue_report(**metadata)
    assert store.db.total_changes == changes
    assert snapshot(store) == before
    audit = store.db.execute("SELECT * FROM report_replays").fetchall()
    assert len(audit) == 1
    assert audit[0]["actor"] == metadata["actor"]
    assert audit[0]["event_id"] == metadata["event_id"]
    assert audit[0]["reason"] == metadata["reason"]
    assert audit[0]["created_at"]


@pytest.mark.parametrize("field", ["event_id", "actor", "reason"])
def test_08_operation_parameter_conflict_no_change(
    ledger: tuple[Store, dict[str, str]],
    field: str,
) -> None:
    store, metadata = ledger
    store.requeue_report(**metadata)
    before = snapshot(store)
    value = str(uuid4()) if field == "event_id" else "different"
    with pytest.raises(ValueError, match="operation_id_conflict"):
        store.requeue_report(**(metadata | {field: value}))
    assert snapshot(store) == before


def test_09_real_audit_insert_failure_rolls_back_event(
    ledger: tuple[Store, dict[str, str]],
) -> None:
    store, metadata = ledger
    store.db.execute(
        "CREATE TRIGGER fail_audit BEFORE INSERT ON report_replays "
        "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
    )
    before = snapshot(store)
    with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
        store.requeue_report(**metadata)
    assert snapshot(store) == before
    store.db.execute("DROP TRIGGER fail_audit")
    assert store.requeue_report(**metadata)


def test_10_foreign_tenant_cannot_replay_or_reuse_operation(
    ledger: tuple[Store, dict[str, str]],
) -> None:
    store, metadata = ledger
    for already_replayed in (False, True):
        if already_replayed:
            store.requeue_report(**metadata)
        before = snapshot(store)
        with pytest.raises(ValueError, match="identity_mismatch"):
            store.requeue_report(**(metadata | {"tenant_id": "attacker-tenant"}))
        assert snapshot(store) == before


def test_11_ack_confirmation_required_before_terminal_claim(
    ledger: tuple[Store, dict[str, str]],
) -> None:
    store, metadata = ledger
    command = str(reports(store)[0]["command_id"])
    store.finish(command)
    assert store.pending_report() is None
    store.requeue_report(**metadata)
    ack = store.pending_report()
    assert ack is not None and json.loads(ack["payload"])["status"] == "acknowledged"
    store.report_result(ack["sequence"], 503, 3)
    assert store.pending_report() is None
    store.report_result(ack["sequence"], 204, 4)
    terminal = store.pending_report()
    assert terminal is not None and json.loads(terminal["payload"])["status"] == "succeeded"


def test_12_reopen_preserves_identity_state_audit_and_order(
    ledger: tuple[Store, dict[str, str]],
) -> None:
    store, metadata = ledger
    store.finish(str(reports(store)[0]["command_id"]))
    store.requeue_report(**metadata)
    before = snapshot(store)
    path = store.path
    store.close()
    recovered = Store(path)
    try:
        assert snapshot(recovered) == before
        assert not recovered.requeue_report(**metadata)
        with pytest.raises(ValueError, match="identity_mismatch"):
            recovered.requeue_report(**(metadata | {"tenant_id": "foreign"}))
        assert snapshot(recovered) == before
        ack = recovered.pending_report()
        assert ack is not None and json.loads(ack["payload"])["status"] == "acknowledged"
        recovered.report_result(ack["sequence"], 204, 3)
        terminal = recovered.pending_report()
        assert terminal is not None and json.loads(terminal["payload"])["status"] == "succeeded"
    finally:
        recovered.close()


def test_authenticated_tenant_cannot_override_scope(ledger: tuple[Store, dict[str, str]]) -> None:
    from enterprise_platform.security.context import SecurityContext, bind_security_context
    from enterprise_platform.security.identity import Principal, PrincipalType

    store, metadata = ledger
    before = snapshot(store)
    context = SecurityContext(Principal("attacker", PrincipalType.USER, tenant_id="foreign"))
    with bind_security_context(context), pytest.raises(ValueError, match="identity_mismatch"):
        store.requeue_report(**metadata)
    assert snapshot(store) == before
