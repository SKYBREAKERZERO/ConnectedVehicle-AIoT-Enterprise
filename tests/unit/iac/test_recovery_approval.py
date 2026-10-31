"""Offline approval contracts including one bounded two-process SQLite race."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.deploy_governance import ROOT
from scripts.iac.plan_admission import BOUND, canonical_digest
from scripts.iac.recovery_approval import RecoveryApprovals
from scripts.iac.release_admission import ReleaseStore
from tests.unit.iac.test_trusted_state_registry import (
    NOW,
    SOURCE,
    TARGET,
    FakeClock,
    fake_identity,
    registry,
    state,
)

OLD_PLAN = b"old saved plan"
NEW_PLAN = b"new saved plan after recovery"


def manifest_for(record: dict[str, Any], plan: bytes) -> dict[str, Any]:
    import hashlib

    return {
        "commit": record["commit"],
        "run_id": record["run_id"],
        "environment": record["environment"],
        "account": record["account"],
        "plan_role": f"arn:aws:iam::{record['account']}:role/plan-reader",
        "apply_role": f"arn:aws:iam::{record['account']}:role/apply-writer",
        "state_bucket": record["bucket"],
        "state_key": record["key"],
        "state_region": "ap-northeast-1",
        "state_kms_key_arn": (
            f"arn:aws:kms:ap-northeast-1:{record['account']}:key/"
            "11111111-1111-1111-1111-111111111111"
        ),
        "state_lineage": record["lineage"],
        "state_serial": record["serial"],
        "lockfile_sha256": "c" * 64,
        "terraform_version": "1.14.7",
        "plan_sha256": hashlib.sha256(plan).hexdigest(),
        "created_at": (NOW - timedelta(minutes=2)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=15)).isoformat(),
    }


def evidence_for(manifest: dict[str, Any], request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "manifest_sha256": canonical_digest(manifest),
        "source_sha256": "d" * 64,
        "run_id": manifest["run_id"],
        "repository": "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise",
        "workflow": ".github/workflows/ci.yml",
        "conclusion": "success",
        "created_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
    }


def seed_interrupted(path: Path, record: dict[str, Any]) -> None:
    store = ReleaseStore(path)
    manifest = manifest_for(record, OLD_PLAN)
    evidence = evidence_for(manifest, "previous-release")
    args: dict[str, Any] = {
        "manifest": manifest,
        "plan": OLD_PLAN,
        "expected": {k: manifest[k] for k in BOUND},
        "evidence": evidence,
        "source": "d" * 64,
        "now": NOW,
        "evidence_authority": lambda _: True,
    }
    store.request("previous-release", manifest, evidence, "d" * 64, "requester")
    store.advance("previous-release", "VERIFIED", **args)
    approval = {
        "request_id": "previous-release",
        "binding_sha256": canonical_digest(
            {"manifest": manifest, "evidence": evidence, "source": "d" * 64}
        ),
        "reviewer": "reviewer",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "approval_id": "previous-approval",
    }
    store.advance(
        "previous-release", "APPROVED", **args, approval=approval, approval_authority=lambda _: True
    )
    store.advance(
        "previous-release", "READY", **args, approval=approval, approval_authority=lambda _: True
    )
    store.interrupt("previous-release")


def open_approvals(path: Path, clock: FakeClock | None = None) -> RecoveryApprovals:
    return RecoveryApprovals(
        path,
        registry=registry(path),
        targets=(TARGET,),
        requesters=frozenset({"requester", "other-requester"}),
        reviewers=frozenset({"reviewer", "requester", "reviewer-two"}),
        authenticate=fake_identity,
        clock=FakeClock() if clock is None else clock,
    )


def setup_approval(
    path: Path,
) -> tuple[RecoveryApprovals, FakeClock, dict[str, Any], dict[str, Any]]:
    clock = FakeClock()
    store = open_approvals(path, clock)
    raw, record = state()
    store.registry.register(raw, record, actor="publisher")
    seed_interrupted(path, record)
    request = store.request(
        "recovery-1",
        record=record,
        target=TARGET,
        previous_release_id="previous-release",
        actor="requester",
    )
    return store, clock, record, request


def test_approval_single_consumption_is_persistent_and_does_not_execute_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "governance.sqlite"
    store, _, _, _ = setup_approval(path)
    approval = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    receipt = store.consume(approval, actor="requester")
    assert open_approvals(path).validate_consumed(receipt, actor="requester")["target"] == TARGET
    with pytest.raises(ValueError, match="consumed"):
        open_approvals(path).consume(approval, actor="requester")
    assert ReleaseStore(path).state("previous-release") == "INTERRUPTED"


@pytest.mark.parametrize("reviewer", ["requester", "REQUESTER", "attacker"])
def test_self_review_or_unlisted_reviewer_is_denied(tmp_path: Path, reviewer: str) -> None:
    store, _, _, _ = setup_approval(tmp_path / "governance.sqlite")
    with pytest.raises(ValueError):
        store.approve("recovery-1", "approval-1", reviewer=reviewer)


@pytest.mark.parametrize(
    "field",
    [
        "request_id",
        "request_sha256",
        "reviewer",
        "approved_at",
        "expires_at",
        "approval_id",
        "approval_sha256",
    ],
)
def test_approval_content_substitution_is_denied_without_consuming(
    tmp_path: Path, field: str
) -> None:
    path = tmp_path / "governance.sqlite"
    store, _, _, _ = setup_approval(path)
    approval = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    changed = {**approval, field: "substituted"}
    with pytest.raises(ValueError):
        store.consume(changed, actor="requester")
    store.consume(approval, actor="requester")
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0] == 1


@pytest.mark.parametrize(
    "case",
    [
        "expired",
        "revoked",
        "other-consumer",
        "source-revoked",
        "source-superseded",
        "clock-regressed",
    ],
)
def test_invalid_approval_or_source_cannot_be_consumed(tmp_path: Path, case: str) -> None:
    store, clock, record, _ = setup_approval(tmp_path / "governance.sqlite")
    approval = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    actor = "requester"
    if case == "expired":
        clock.now += timedelta(minutes=6)
    if case == "revoked":
        store.revoke("approval-1", reviewer="reviewer")
    if case == "other-consumer":
        actor = "other-requester"
    if case == "source-revoked":
        store.registry.revoke(record, actor="publisher")
    if case == "source-superseded":
        raw, new = state(serial=10, version="state-v10")
        store.registry.register(raw, new, actor="publisher")
    if case == "clock-regressed":
        clock.now -= timedelta(minutes=1)
    with pytest.raises(ValueError):
        store.consume(approval, actor=actor)


def test_request_and_target_replacement_or_reapproval_are_denied(tmp_path: Path) -> None:
    store, _, record, _ = setup_approval(tmp_path / "governance.sqlite")
    with pytest.raises(ValueError):
        store.request(
            "another",
            record=record,
            target=SOURCE,
            previous_release_id="previous-release",
            actor="requester",
        )
    store.approve("recovery-1", "approval-1", reviewer="reviewer")
    with pytest.raises(ValueError):
        store.approve("recovery-1", "replacement", reviewer="reviewer-two")
    with pytest.raises(ValueError):
        store.request(
            "unregistered",
            record={**record, "version_id": "unknown"},
            target=TARGET,
            previous_release_id="previous-release",
            actor="requester",
        )


def test_revocation_and_expiry_invalidate_an_already_consumed_receipt(tmp_path: Path) -> None:
    store, clock, _, _ = setup_approval(tmp_path / "governance.sqlite")
    approval = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    receipt = store.consume(approval, actor="requester")
    changed = {**receipt, "consumer": "other-requester"}
    with pytest.raises(ValueError):
        store.validate_consumed(changed, actor="other-requester")
    clock.now += timedelta(minutes=6)
    with pytest.raises(ValueError):
        store.validate_consumed(receipt, actor="requester")
    clock.now = NOW
    store.revoke("approval-1", reviewer="reviewer")
    with pytest.raises(ValueError):
        store.validate_consumed(receipt, actor="requester")
    with pytest.raises(ValueError):
        store.consume(approval, actor="requester")


def test_two_processes_can_adopt_only_one_approval(tmp_path: Path) -> None:
    path = tmp_path / "governance.sqlite"
    store, _, _, _ = setup_approval(path)
    approval = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    token = tmp_path / "token.json"
    token.write_text(json.dumps(approval), encoding="utf-8")
    start = tmp_path / "start"
    code = """
import json,sys,time
from pathlib import Path
from tests.unit.iac.test_recovery_approval import open_approvals
store=open_approvals(Path(sys.argv[1]));token=json.loads(Path(sys.argv[2]).read_text())
Path(sys.argv[4]).write_text('ready')
deadline=time.monotonic()+8
while not Path(sys.argv[3]).exists():
    if time.monotonic()>deadline:sys.exit(99)
    time.sleep(.01)
try:store.consume(token,actor='requester')
except ValueError:sys.exit(23)
sys.exit(0)
"""
    processes = []
    try:
        for number in range(2):
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        code,
                        str(path),
                        str(token),
                        str(start),
                        str(tmp_path / f"ready-{number}"),
                    ],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        deadline = time.monotonic() + 8
        while not all((tmp_path / f"ready-{number}").exists() for number in range(2)):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        start.write_text("go")
        outputs = [p.communicate(timeout=10) for p in processes]
        assert sorted(p.returncode for p in processes) == [0, 23], outputs
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT count(*) FROM day29_consumptions").fetchone()[0] == 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
