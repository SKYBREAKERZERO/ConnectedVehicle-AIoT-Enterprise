"""New release verification uses real local stores and simulated trusted producers."""

from __future__ import annotations

import hashlib
import sqlite3
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.plan_admission import BOUND
from scripts.iac.release_revalidation import ReleaseRevalidator
from tests.unit.iac.test_recovery_approval import (
    NEW_PLAN,
    OLD_PLAN,
    evidence_for,
    manifest_for,
    setup_approval,
)
from tests.unit.iac.test_trusted_state_registry import TARGET, registry, state


def clear_plan() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.7",
        "complete": True,
        "errored": False,
        "resource_changes": [],
        "resource_drift": [],
        "output_changes": {},
    }


def setup_revalidation(
    path: Path, *, target_run: str = "222:1"
) -> tuple[ReleaseRevalidator, dict[str, Any], Any]:
    approvals, clock, _, _ = setup_approval(path)
    approval = approvals.approve("recovery-1", "approval-1", reviewer="reviewer")
    receipt = approvals.consume(approval, actor="requester")
    target = registry(path, TARGET)
    raw, record = state(TARGET, version="restored-v9", commit="b" * 40, run_id=target_run)
    target.register(raw, record, actor="publisher")
    verifier = ReleaseRevalidator(
        path,
        registry=target,
        approvals=approvals,
        evidence_authority=lambda _: True,
        observation_authority=lambda _: True,
        clock=clock,
    )
    manifest = manifest_for(record, NEW_PLAN)
    manifest["created_at"] = receipt["consumed_at"]
    args: dict[str, Any] = {
        "receipt": receipt,
        "actor": "requester",
        "raw": raw,
        "record": record,
        "manifest": manifest,
        "plan": NEW_PLAN,
        "expected": {k: manifest[k] for k in BOUND},
        "evidence": evidence_for(manifest, "new-release"),
        "source": "d" * 64,
        "refresh_code": 0,
        "refresh_plan": clear_plan(),
        "normal_code": 0,
        "normal_plan": clear_plan(),
    }
    args["evidence"]["created_at"] = receipt["consumed_at"]
    return verifier, args, clock


def test_fresh_registered_recovery_can_only_reach_verified_not_apply(tmp_path: Path) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    result = verifier.verify("new-release", **args)
    assert result["status"] == "VERIFIED" and result["apply_authorized"] is False
    assert result["new_release_approval_required"] and not result["production_identity_verified"]
    assert verifier.releases.state("new-release") == "VERIFIED"
    assert verifier.releases.state("previous-release") == "INTERRUPTED"


@pytest.mark.parametrize(
    "case",
    [
        "old-plan",
        "old-run",
        "commit",
        "state-version",
        "state-serial",
        "state-bytes",
        "expected-account",
        "expected-state",
        "old-evidence",
        "source",
        "unconsumed-receipt",
        "wrong-target",
        "expired",
    ],
)
def test_stale_or_substituted_revalidation_inputs_are_rejected(tmp_path: Path, case: str) -> None:
    verifier, args, clock = setup_revalidation(tmp_path / "governance.sqlite")
    if case == "old-plan":
        args["plan"] = OLD_PLAN
        args["manifest"]["plan_sha256"] = hashlib.sha256(OLD_PLAN).hexdigest()
    if case == "old-run":
        args["manifest"]["run_id"] = "111:1"
    if case == "commit":
        args["manifest"]["commit"] = "a" * 40
    if case == "state-version":
        args["record"]["version_id"] = "unregistered"
    if case == "state-serial":
        args["record"]["serial"] = 8
    if case == "state-bytes":
        args["raw"] += b"changed"
    if case == "expected-account":
        args["expected"]["account"] = "999999999999"
    if case == "expected-state":
        args["expected"]["state_serial"] = 10
    if case == "old-evidence":
        args["evidence"]["run_id"] = "111:1"
    if case == "source":
        args["source"] = "e" * 64
    if case == "unconsumed-receipt":
        args["receipt"]["receipt_sha256"] = "f" * 64
    if case == "wrong-target":
        args["record"]["bucket"] = "another-bucket"
    if case == "expired":
        clock.now += timedelta(minutes=6)
    with pytest.raises(ValueError):
        verifier.verify("new-release", **args)
    assert verifier.releases.state("previous-release") == "INTERRUPTED"


@pytest.mark.parametrize(
    "case", ["normal-drift", "state-drift", "plan-error", "incomplete", "code-contradiction"]
)
def test_drift_or_unreliable_dual_plan_prohibits_verified(tmp_path: Path, case: str) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    if case == "normal-drift":
        args["normal_code"] = 2
        args["normal_plan"]["resource_changes"] = [{"change": {"actions": ["update"]}}]
    if case == "state-drift":
        args["refresh_code"] = 2
        args["refresh_plan"]["resource_drift"] = [{"change": {"actions": ["update"]}}]
    if case == "plan-error":
        args["normal_code"] = 1
    if case == "incomplete":
        args["normal_plan"]["complete"] = False
    if case == "code-contradiction":
        args["normal_plan"]["resource_changes"] = [{"change": {"actions": ["update"]}}]
    with pytest.raises(ValueError, match="drift/error"):
        verifier.verify("new-release", **args)


def test_interrupted_id_and_receipt_reuse_cannot_create_another_verified_request(
    tmp_path: Path,
) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    with pytest.raises(ValueError, match="cannot be resumed"):
        verifier.verify("previous-release", **args)
    verifier.verify("new-release", **args)
    with pytest.raises(ValueError):
        verifier.verify("new-release", **args)
    args["evidence"]["request_id"] = "another-release"
    with pytest.raises(ValueError, match="already claimed"):
        verifier.verify("another-release", **args)


@pytest.mark.parametrize("case", ["approval", "source-version", "target-version"])
def test_revoked_authorities_block_release_verification(tmp_path: Path, case: str) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    if case == "approval":
        verifier.approvals.revoke("approval-1", reviewer="reviewer")
    if case == "source-version":
        verifier.approvals.registry.revoke(
            args["receipt"]["request"]["source_record"], actor="publisher"
        )
    if case == "target-version":
        verifier.registry.revoke(args["record"], actor="publisher")
    with pytest.raises(ValueError):
        verifier.verify("new-release", **args)


def test_revocation_between_initial_check_and_day27_commit_is_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    original = verifier.releases.request

    def request_then_revoke(*values: Any, **options: Any) -> None:
        original(*values, **options)
        verifier.registry.revoke(args["record"], actor="publisher")

    monkeypatch.setattr(verifier.releases, "request", request_then_revoke)
    with pytest.raises(ValueError):
        verifier.verify("new-release", **args)
    assert verifier.releases.state("new-release") == "REJECTED"
    with sqlite3.connect(verifier.path) as connection:
        assert (
            connection.execute("SELECT status FROM day29_revalidations").fetchone()[0] == "REJECTED"
        )


def test_drift_attestation_binds_the_actual_new_plan_and_fails_closed(tmp_path: Path) -> None:
    verifier, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    observations = []

    def authority(payload: dict[str, Any]) -> bool:
        observations.append(deepcopy(payload))
        return False

    verifier = ReleaseRevalidator(
        verifier.path,
        registry=verifier.registry,
        approvals=verifier.approvals,
        evidence_authority=lambda _: True,
        observation_authority=authority,
        clock=verifier._clock,
    )
    with pytest.raises(ValueError, match="not authenticated"):
        verifier.verify("new-release", **args)
    assert observations[0]["normal_plan_sha256"] and observations[0]["refresh_plan_sha256"]
