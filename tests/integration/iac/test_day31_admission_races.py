"""F07-F10: real local process interleavings over the existing governance ledger."""

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

from tests.integration.iac import test_day30_failure_isolation as day30
from tests.integration.iac.test_day29_process_faults import bundle
from tests.unit.iac.test_release_revalidation import setup_revalidation


@pytest.fixture(scope="module")
def results(record_testsuite_property: Callable[[str, object], None]) -> Iterator[dict[str, Any]]:
    from scripts.iac.day31_evidence import provenance

    p = provenance()
    for k, v in p.items():
        record_testsuite_property(k, v)
    data: dict[str, Any] = {"provenance": p, "revocation": []}
    yield data
    if name := os.environ.get("DAY31_FAULT_REPORT"):
        Path(name).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def test_partial_commit_and_reconciled_replay_are_blocked(
    tmp_path: Path, results: dict[str, Any]
) -> None:
    facts: dict[str, Any] = {}
    first = tmp_path / "crash"
    first.mkdir()
    second = tmp_path / "ack"
    second.mkdir()
    day30.test_crash_after_day27_verified_is_quarantined(first, facts)
    day30.test_reconciliation_never_promotes_to_ready(second, facts)
    results["isolation"] = {
        "crash": {
            k: facts["crash"][k]
            for k in (
                "quarantines",
                "audit_matches",
                "audit_failure_rollback_counts",
                "original_rows_preserved",
            )
        },
        "reconciled": {
            k: facts["reconciliation"][k]
            for k in ("original_rows_preserved", "reconciled_still_denied")
        },
    }


def test_unknown_commit_race_and_bounded_lock_never_reconsume(
    tmp_path: Path, results: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.iac.test_failure_isolation import (
        test_locked_transaction_is_bounded_and_does_not_retry_adoption,
    )

    facts: dict[str, Any] = {}
    for name in ("unknown", "race", "lock"):
        (tmp_path / name).mkdir()
    with monkeypatch.context() as scoped:
        day30.test_unknown_commit_result_never_reuses_approval(tmp_path / "unknown", facts, scoped)
    day30.test_two_reconcilers_create_one_quarantine(tmp_path / "race", facts)
    test_locked_transaction_is_bounded_and_does_not_retry_adoption(tmp_path / "lock")
    results["unknown"] = {
        k: facts["unknown"][k]
        for k in ("consumptions", "consumption_audits", "commit_lookup_matches")
    }
    results["race"] = facts["race"]
    with sqlite3.connect(tmp_path / "lock/governance.sqlite") as c:
        results["lock_consumptions"] = c.execute(
            "SELECT count(*) FROM day29_consumptions"
        ).fetchone()[0]


WORKER = """
import base64,json,sys,time
from pathlib import Path
from datetime import timedelta
from tests.unit.iac.test_recovery_approval import open_approvals
from tests.unit.iac.test_trusted_state_registry import NOW
from scripts.iac.release_admission import ReleaseStore
from scripts.iac.plan_admission import canonical_digest
p=Path(sys.argv[1]);role=sys.argv[2];root=Path(sys.argv[3])
v=json.loads((root/'args.json').read_text());a=v['args']
a['plan']=base64.b64decode(a['plan'])
store=ReleaseStore(p,clock=lambda:NOW)
approval=open_approvals(p)
(root/(role+'-ready')).write_text('ready')
def wait(name):
    end=time.monotonic()+15
    while not (root/name).exists():
        if time.monotonic()>end:raise RuntimeError('barrier timeout')
        time.sleep(.01)
def held(*a):
    (root/(role+'-held')).write_text('writer held')
    wait(role+'-release');return True
wait(role+'-go');(root/(role+'-attempt')).write_text('attempt')
try:
    if role=='revoke':
        def authenticate(actor,action,digest):
            return held() if action=='revoke-recovery-approval' else True
        approval._authenticate=authenticate
        approval.revoke('approval-1',reviewer='reviewer')
    else:
        binding={k:a[k] for k in ('manifest','evidence','source')}
        token={'request_id':'new-release','binding_sha256':canonical_digest(binding),
            'reviewer':'independent-reviewer','approved_at':NOW.isoformat(),
            'expires_at':(NOW+timedelta(minutes=5)).isoformat(),
            'approval_id':'fresh-release-review'}
        payload={k:a[k] for k in ('manifest','plan','expected','evidence','source')}
        store.advance('new-release','APPROVED',**payload,now=NOW,
            evidence_authority=held,approval=token,approval_authority=lambda _:True)
except ValueError:sys.exit(23)
sys.exit(0)
"""


@pytest.mark.parametrize("order", ["admission-first", "revoke-first"])
def test_revocation_and_admission_serialize_without_post_revoke_promotion(
    tmp_path: Path, results: dict[str, Any], order: str
) -> None:
    v, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    v.verify("new-release", **args)
    bundle(tmp_path / "args.json", args, "normal", "new-release")
    children = {
        role: subprocess.Popen(
            [sys.executable, "-c", WORKER, str(v.path), role, str(tmp_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for role in ("admit", "revoke")
    }

    def wait(name: str) -> None:
        deadline = time.monotonic() + 15
        while not (tmp_path / name).exists():
            assert time.monotonic() < deadline, name
            time.sleep(0.01)

    try:
        wait("admit-ready")
        wait("revoke-ready")
        first = "admit" if order == "admission-first" else "revoke"
        second = "revoke" if first == "admit" else "admit"
        (tmp_path / (first + "-go")).write_text("go")
        wait(first + "-held")
        (tmp_path / (second + "-go")).write_text("go")
        wait(second + "-attempt")
        (tmp_path / (first + "-release")).write_text("release")
        if order == "admission-first":
            wait("revoke-held")
            (tmp_path / "revoke-release").write_text("release")
        output = {role: p.communicate(timeout=20) for role, p in children.items()}
        assert children["revoke"].returncode == 0, output
        assert children["admit"].returncode == (0 if order == "admission-first" else 23), output
        with pytest.raises(ValueError) as denied:
            v.releases.state("new-release")
        with sqlite3.connect(v.path) as c:
            ready = c.execute("SELECT count(*) FROM releases WHERE state='READY'").fetchone()[0]
            consumed = c.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0]
        assert ready == 0 and consumed == 1
        results["revocation"].append(
            {
                "order": order,
                "admission_exit": children["admit"].returncode,
                "revoke_exit": children["revoke"].returncode,
                "ready_count": ready,
                "consumptions": consumed,
                "post_revoke_denied": issubclass(denied.type, ValueError),
            }
        )
    finally:
        for p in children.values():
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)
