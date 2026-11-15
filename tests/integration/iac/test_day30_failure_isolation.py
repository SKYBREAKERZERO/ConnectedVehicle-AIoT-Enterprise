"""Real local process/SQLite isolation faults; no cloud identity or AWS claims."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.failure_isolation import Quarantined, QuarantineStore
from tests.integration.iac.test_day29_process_faults import CHILD, bundle
from tests.unit.iac.test_release_revalidation import setup_revalidation
from tests.unit.iac.test_trusted_state_registry import NOW


@pytest.fixture(scope="module")
def results(record_testsuite_property: Callable[[str, object], None]) -> Iterator[dict[str, Any]]:
    from scripts.iac.day30_evidence import source_digest

    provenance = {
        "day30_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day30_run_id": run_identity(),
        "day30_source_sha256": source_digest(),
    }
    for k, v in provenance.items():
        record_testsuite_property(k, v)
    data: dict[str, Any] = {"provenance": provenance, "scenarios": {}}
    yield data["scenarios"]
    if name := os.environ.get("DAY30_FAULT_REPORT"):
        Path(name).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def snapshot(db: Path) -> dict[str, list[Any]]:
    with sqlite3.connect(db) as c:
        names = [
            r[0]
            for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if not r[0].startswith("day30_")
        ]
        return {
            name: c.execute("SELECT * FROM " + name + " ORDER BY rowid").fetchall()
            for name in names
        }


def crashed(tmp_path: Path) -> tuple[Any, dict[str, Any], QuarantineStore]:
    db = tmp_path / "governance.sqlite"
    v, args, clock = setup_revalidation(db)
    payload = tmp_path / "private.json"
    bundle(payload, args, "after-verified", "new-release")
    p = subprocess.run(
        [sys.executable, "-c", CHILD, str(db), str(payload)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert p.returncode == 75, p.stderr
    return v, args, QuarantineStore(db, clock=clock)


def counts(db: Path) -> tuple[int, int]:
    with sqlite3.connect(db) as c:
        return (
            c.execute("SELECT count(*) FROM day30_quarantine").fetchone()[0],
            c.execute("SELECT count(*) FROM day30_audit").fetchone()[0],
        )


def test_crash_after_day27_verified_is_quarantined(tmp_path: Path, results: dict[str, Any]) -> None:
    v, _, q = crashed(tmp_path)
    before = snapshot(v.path)
    scan = q.scan()
    assert scan[0]["day27_state"] == "VERIFIED" and scan[0]["day29_state"] == "CLAIMED"
    assert counts(v.path) == (0, 0) and snapshot(v.path) == before
    with sqlite3.connect(v.path) as c:
        c.execute(
            "CREATE TRIGGER reject_day30_audit BEFORE INSERT ON day30_audit "
            "BEGIN SELECT RAISE(ABORT,'injected audit failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        q.quarantine("new-release")
    rollback = counts(v.path)
    assert rollback == (0, 0)
    with sqlite3.connect(v.path) as c:
        c.execute("DROP TRIGGER reject_day30_audit")
    result = q.quarantine("new-release")
    with sqlite3.connect(v.path) as c:
        audit_match = c.execute(
            "SELECT count(*) FROM day30_quarantine q JOIN day30_audit a "
            "ON a.operation_id=q.quarantine_id AND a.evidence_sha256=q.evidence_sha256 "
            "AND a.release_id=q.release_id"
        ).fetchone()[0]
    assert counts(v.path) == (1, 1) and audit_match == 1 and snapshot(v.path) == before
    results["crash"] = {
        "day27_state": scan[0]["day27_state"],
        "day29_state": scan[0]["day29_state"],
        "quarantines": counts(v.path)[0],
        "audit_matches": audit_match,
        "audit_failure_rollback_counts": list(rollback),
        "original_rows_preserved": snapshot(v.path) == before,
        "lookup_matches": q.lookup(result["operation_id"]) == result,
    }


RECONCILER = """
import sys,time
from pathlib import Path
from scripts.iac.failure_isolation import QuarantineStore
from tests.unit.iac.test_trusted_state_registry import NOW
p=Path(sys.argv[2]);p.write_text('ready');end=time.monotonic()+15
while not Path(sys.argv[3]).exists():
    if time.monotonic()>end:sys.exit(99)
    time.sleep(.02)
print(QuarantineStore(Path(sys.argv[1]),clock=lambda:NOW).quarantine('new-release')['operation_id'])
"""


def test_two_reconcilers_create_one_quarantine(tmp_path: Path, results: dict[str, Any]) -> None:
    v, _, q = crashed(tmp_path)
    start = tmp_path / "start"
    children = []
    try:
        for i in range(2):
            children.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        RECONCILER,
                        str(v.path),
                        str(tmp_path / f"ready-{i}"),
                        str(start),
                    ],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        deadline = time.monotonic() + 15
        while not all((tmp_path / f"ready-{i}").exists() for i in range(2)):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        start.write_text("go")
        outputs = [p.communicate(timeout=25) for p in children]
        codes = [p.returncode for p in children]
        ids = {out[0].strip() for out in outputs}
        assert codes == [0, 0], outputs
        q.quarantine("new-release")
        assert counts(v.path) == (1, 1) and len(ids) == 1
        results["race"] = {
            "exit_codes": codes,
            "unique_operations": len(ids),
            "quarantines": counts(v.path)[0],
            "audits": counts(v.path)[1],
        }
    finally:
        for p in children:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)


def advance_args(args: dict[str, Any]) -> dict[str, Any]:
    return {
        **{k: args[k] for k in ("manifest", "plan", "expected", "evidence", "source")},
        "now": NOW,
        "evidence_authority": lambda _: True,
    }


def test_quarantine_blocks_release_admission(tmp_path: Path, results: dict[str, Any]) -> None:
    v, args, q = crashed(tmp_path)
    # Inconsistent durable state is already denied before explicit quarantine.
    with pytest.raises(Quarantined):
        v.releases.advance("new-release", "APPROVED", **advance_args(args))
    q.quarantine("new-release")
    before = snapshot(v.path)

    def advance_to(target: str) -> Callable[[], None]:
        return lambda: v.releases.advance("new-release", target, **advance_args(args))

    actions: dict[str, Callable[[], Any]] = {
        "request": lambda: v.releases.request(
            "new-release", args["manifest"], args["evidence"], args["source"], "requester"
        ),
        "state": lambda: v.releases.state("new-release"),
        **{target: advance_to(target) for target in ("VERIFIED", "APPROVED", "READY")},
        "interrupt": lambda: v.releases.interrupt("new-release"),
        "revalidate": lambda: v.verify("new-release", **args),
        "receipt": lambda: v.approvals.validate_consumed(args["receipt"], actor="requester"),
        "lookup": lambda: v.approvals.recover_consumed(
            args["receipt"]["approval"], actor="requester"
        ),
    }
    denied = []
    for name, action in actions.items():
        with pytest.raises(Quarantined):
            action()
        denied.append(name)
    assert snapshot(v.path) == before
    results["admission"] = {
        "entries": sorted(actions),
        "denied": sorted(denied),
        "original_rows_preserved": snapshot(v.path) == before,
    }


def test_quarantine_does_not_affect_other_release(tmp_path: Path, results: dict[str, Any]) -> None:
    v, args, q = crashed(tmp_path)
    q.quarantine("new-release")
    with sqlite3.connect(v.path) as c:
        original = c.execute("SELECT binding,state FROM releases WHERE id='new-release'").fetchone()
    request = args["receipt"]["request"]
    v.approvals.request(
        "recovery-other",
        record=request["source_record"],
        target=request["target"],
        previous_release_id="previous-release",
        actor="requester",
    )
    token = v.approvals.approve("recovery-other", "approval-other", reviewer="reviewer")
    other = {
        **args,
        "receipt": v.approvals.consume(token, actor="requester"),
        "evidence": {**args["evidence"], "request_id": "other-release"},
    }
    accepted = v.verify("other-release", **other)
    with sqlite3.connect(v.path) as c:
        unchanged = (
            c.execute("SELECT binding,state FROM releases WHERE id='new-release'").fetchone()
            == original
        )
        receipts = c.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0]
    assert (
        unchanged and v.releases.state("other-release") == "VERIFIED" and counts(v.path) == (1, 1)
    )
    results["isolation"] = {
        "unrelated_state": accepted["status"],
        "failed_release_preserved": unchanged,
        "quarantines": counts(v.path)[0],
        "consumptions": receipts,
        "apply_authorized": accepted["apply_authorized"],
    }


def test_unknown_commit_result_never_reuses_approval(
    tmp_path: Path, results: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.iac import failure_isolation as module
    from tests.unit.iac.test_recovery_approval import open_approvals, setup_approval

    db = tmp_path / "lost.sqlite"
    approvals, _, _, _ = setup_approval(db)
    token = approvals.approve("recovery-1", "approval-1", reviewer="reviewer")
    private = tmp_path / "approval.json"
    private.write_text(json.dumps(token))
    code = (
        "from pathlib import Path;import json,sys,os;"
        "from tests.unit.iac.test_recovery_approval import open_approvals;"
        "a=open_approvals(Path(sys.argv[1]));"
        "a.consume(json.loads(Path(sys.argv[2]).read_text()),actor='requester');os._exit(73)"
    )
    child = subprocess.run(
        [sys.executable, "-c", code, str(db), str(private)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert child.returncode == 73, child.stderr
    reopened = open_approvals(db)
    receipt = reopened.recover_consumed(token, actor="requester")
    with pytest.raises(ValueError):
        reopened.consume(token, actor="requester")
    with sqlite3.connect(db) as c:
        consumed = c.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0]
        audits = c.execute(
            "SELECT count(*) FROM day29_audit WHERE action='CONSUME_RECOVERY'"
        ).fetchone()[0]
    v, _, q = crashed(tmp_path)
    commit = module._commit

    def lost(c: sqlite3.Connection) -> None:
        commit(c)
        raise sqlite3.OperationalError("injected lost commit response")

    monkeypatch.setattr(module, "_commit", lost)
    outcome = q.quarantine("new-release")
    assert q.lookup(outcome["operation_id"]) == outcome and counts(v.path) == (1, 1)
    assert consumed == audits == 1 and receipt["consumer"] == "requester"
    results["unknown"] = {
        "consumptions": consumed,
        "consumption_audits": audits,
        "lookup_consumer": receipt["consumer"],
        "quarantines": counts(v.path)[0],
        "quarantine_audits": counts(v.path)[1],
        "commit_lookup_matches": q.lookup(outcome["operation_id"]) == outcome,
    }


def test_reconciliation_never_promotes_to_ready(tmp_path: Path, results: dict[str, Any]) -> None:
    v, _, q = crashed(tmp_path)
    before = snapshot(v.path)
    q.scan()
    q.scan()
    q.quarantine("new-release")
    q.quarantine("new-release")
    assert snapshot(v.path) == before
    # Even acknowledged isolation cannot revive a release/receipt. There is no
    # API that resets a receipt, claim or Release; administrators are out of scope.
    from scripts.iac.plan_admission import canonical_digest

    operation = canonical_digest({"action": "quarantine", "release_id": "new-release"})
    q.acknowledge(operation)
    q.acknowledge(operation)
    with pytest.raises(Quarantined) as denied:
        v.releases.state("new-release")
    assert snapshot(v.path) == before
    results["reconciliation"] = {
        "original_rows_preserved": snapshot(v.path) == before,
        "quarantines": counts(v.path)[0],
        "audits": counts(v.path)[1],
        "reconciled_still_denied": denied.type is Quarantined,
    }
