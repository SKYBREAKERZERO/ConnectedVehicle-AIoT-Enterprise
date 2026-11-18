"""Day30 policy, bounded locks, ownership and evidence-negative contracts."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest

from scripts.iac.failure_isolation import IsolationUnavailable, Quarantined, QuarantineStore
from tests.unit.iac.test_release_revalidation import setup_revalidation
from tests.unit.iac.test_trusted_state_registry import registry


@pytest.fixture(scope="module", autouse=True)
def stamp(record_testsuite_property: Callable[[str, object], None]) -> None:
    from scripts.iac.day30_evidence import provenance

    for k, v in provenance().items():
        record_testsuite_property(k, v)


def test_locked_transaction_is_bounded_and_does_not_retry_adoption(tmp_path: Path) -> None:
    v, args, clock = setup_revalidation(tmp_path / "governance.sqlite")
    v.verify("new-release", **args)
    v.registry.revoke(args["record"], actor="publisher")
    q = QuarantineStore(v.path, clock=clock)
    with sqlite3.connect(v.path) as holder:
        holder.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        with pytest.raises(IsolationUnavailable, match="operation_id="):
            q.quarantine("new-release")
        assert time.monotonic() - started < 1.5
        assert holder.execute("SELECT count(*) FROM day30_quarantine").fetchone()[0] == 0
        assert holder.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0] == 1
    q.quarantine("new-release")
    with pytest.raises(Quarantined):
        v.releases.state("new-release")


def test_state_head_change_only_invalidates_exact_related_bindings(tmp_path: Path) -> None:
    v, args, clock = setup_revalidation(tmp_path / "governance.sqlite")
    v.verify("new-release", **args)
    v.registry.revoke(args["record"], actor="publisher")
    q = QuarantineStore(v.path, clock=clock)
    assert q.scan()[0]["reason_code"] == "STATE_HEAD_CHANGED"
    with pytest.raises(Quarantined):
        v.releases.state("new-release")
    q.quarantine("new-release")
    # New Day30 schema is explicitly allowed; arbitrary business tables still aren't.
    registry(v.path)
    with sqlite3.connect(v.path) as c:
        c.execute("CREATE TABLE business_data(id INTEGER)")
    with pytest.raises(ValueError, match="business DB"):
        registry(v.path)


@pytest.mark.parametrize("case", ["plan", "drift", "forged-receipt", "wrong-actor"])
def test_bad_preflight_isolates_only_authenticated_unowned_request(
    tmp_path: Path, case: str
) -> None:
    v, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    if case == "plan":
        args["plan"] += b"wrong"
    if case == "drift":
        args["normal_code"] = 1
    if case == "forged-receipt":
        args["receipt"]["receipt_sha256"] = "0" * 64
    if case == "wrong-actor":
        args["actor"] = "intruder"
    with pytest.raises(ValueError):
        v.verify("new-release", **args)
    with sqlite3.connect(v.path) as c:
        rows = c.execute("SELECT release_id,reason_code FROM day30_quarantine").fetchall()
        assert rows == (
            [("new-release", "PLAN_SHA_MISMATCH" if case == "plan" else "DRIFT_REVIEW_REQUIRED")]
            if case in {"plan", "drift"}
            else []
        )
        assert c.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0] == 1


def test_losing_request_cannot_quarantine_completed_winner(tmp_path: Path) -> None:
    v, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    v.verify("new-release", **args)
    args["evidence"] = {**args["evidence"], "request_id": "loser"}
    with pytest.raises(ValueError):
        v.verify("loser", **args)
    assert v.releases.state("new-release") == "VERIFIED"
    with sqlite3.connect(v.path) as c:
        assert c.execute("SELECT count(*) FROM day30_quarantine").fetchone()[0] == 0


@pytest.mark.parametrize(
    "change",
    [
        "failed",
        "skip",
        "missing",
        "duplicate",
        "old-run",
        "source",
        "counter",
        "empty",
        "disabled-guard",
        "extra-claim",
    ],
)
def test_evidence_rejects_incomplete_replayed_or_ineffective_isolation(
    tmp_path: Path, change: str
) -> None:
    from scripts.iac.day30_evidence import ENTRIES, SCENARIOS, fault_evidence

    expected = {"day30_commit": "a" * 40, "day30_run_id": "123:1", "day30_source_sha256": "b" * 64}
    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite")
    props = ElementTree.SubElement(suite, "properties")
    for k, v in expected.items():
        ElementTree.SubElement(props, "property", name=k, value=v)
    for name in sorted(SCENARIOS):
        ElementTree.SubElement(suite, "testcase", name=name)
    scenarios: dict[str, Any] = {
        "crash": {
            "day27_state": "VERIFIED",
            "day29_state": "CLAIMED",
            "quarantines": 1,
            "audit_matches": 1,
            "audit_failure_rollback_counts": [0, 0],
            "original_rows_preserved": True,
            "lookup_matches": True,
        },
        "race": {"exit_codes": [0, 0], "unique_operations": 1, "quarantines": 1, "audits": 1},
        "admission": {
            "entries": sorted(ENTRIES),
            "denied": sorted(ENTRIES),
            "original_rows_preserved": True,
        },
        "isolation": {
            "unrelated_state": "VERIFIED",
            "failed_release_preserved": True,
            "quarantines": 1,
            "consumptions": 2,
            "apply_authorized": False,
        },
        "unknown": {
            "consumptions": 1,
            "consumption_audits": 1,
            "lookup_consumer": "requester",
            "quarantines": 1,
            "quarantine_audits": 1,
            "commit_lookup_matches": True,
        },
        "reconciliation": {
            "original_rows_preserved": True,
            "quarantines": 1,
            "audits": 2,
            "reconciled_still_denied": True,
        },
    }
    data = {"provenance": dict(expected), "scenarios": scenarios}
    if change == "failed":
        ElementTree.SubElement(suite[-1], "failure")
    if change == "skip":
        ElementTree.SubElement(suite[-1], "skipped")
    if change == "missing":
        suite.remove(suite[-1])
    if change == "duplicate":
        ElementTree.SubElement(suite, "testcase", name=sorted(SCENARIOS)[0])
    if change == "old-run":
        data["provenance"]["day30_run_id"] = "122:1"
    if change == "source":
        data["provenance"]["day30_source_sha256"] = "c" * 64
    if change == "counter":
        suite.set("failures", "1")
    if change == "empty":
        data = {}
    if change == "disabled-guard":
        scenarios["admission"]["denied"] = []
    if change == "extra-claim":
        scenarios["isolation"]["production_identity_verified"] = True
    xml = tmp_path / "fault.xml"
    report = tmp_path / "fault.json"
    ElementTree.ElementTree(root).write(xml)
    report.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        fault_evidence(xml, report, expected)


def test_default_cli_scan_does_not_even_create_isolation_tables(tmp_path: Path) -> None:
    import subprocess
    import sys

    from tests.unit.iac.test_recovery_approval import setup_approval

    db = tmp_path / "governance.sqlite"
    setup_approval(db)
    before = db.read_bytes()
    child = subprocess.run(
        [sys.executable, "-m", "scripts.iac.failure_isolation", "--database", str(db)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == [] and db.read_bytes() == before
