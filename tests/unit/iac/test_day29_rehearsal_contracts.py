"""Explicit rehearsal mode and per-run credential regression contracts."""

from __future__ import annotations

import hashlib
import hmac
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.local_rehearsal_identity import ROLES, LocalRehearsalIdentity
from scripts.iac.plan_admission import BOUND, canonical_digest, plan_errors
from tests.unit.iac.test_plan_admission import NOW, PLAN, manifest
from tests.unit.iac.test_recovery_approval import setup_approval
from tests.unit.iac.test_release_revalidation import setup_revalidation


def local_manifest() -> dict[str, Any]:
    m = manifest()
    m.update(
        account="000000000000",
        environment="local",
        state_key="ota/local/terraform.tfstate",
        state_kms_key_arn="localstack-aes256",
        plan_role="arn:aws:iam::000000000000:role/local-plan",
        apply_role="arn:aws:iam::000000000000:role/local-disabled",
    )
    return m


def test_rehearsal_never_relaxes_the_default_production_contract() -> None:
    m = local_manifest()
    args: dict[str, Any] = {"plan": PLAN, "expected": {k: m[k] for k in BOUND}, "now": NOW}
    assert plan_errors(m, **args)
    assert not plan_errors(m, **args, localstack_rehearsal=True)
    p = manifest()
    assert plan_errors(
        p, plan=PLAN, expected={k: p[k] for k in BOUND}, now=NOW, localstack_rehearsal=True
    )


def authority() -> LocalRehearsalIdentity:
    return LocalRehearsalIdentity(
        b"x" * 32, endpoint="http://127.0.0.1:4566", commit="a" * 40, run_id="123:1"
    )


@pytest.mark.parametrize(
    "field",
    [
        "issuer",
        "audience",
        "account",
        "environment",
        "endpoint",
        "commit",
        "run_id",
        "subject",
        "payload_sha256",
        "signature",
    ],
)
def test_local_credentials_reject_tampering_and_scope_changes(field: str) -> None:
    a = authority()
    token = deepcopy(a.tokens["publisher"])
    if field == "signature":
        token["signature"] = "0" * 64
    else:
        token["claims"][field] = "wrong"
    assert not a.verify(token, "principal", "publisher", {"actions": sorted(ROLES["publisher"])})


def test_signed_but_expired_credential_and_issuer_key_mismatch_are_denied() -> None:
    a = authority()
    token = deepcopy(a.tokens["publisher"])
    token["claims"]["expires_at"] = token["claims"]["issued_at"]
    token["signature"] = hmac.new(
        b"x" * 32, canonical_digest(token["claims"]).encode(), hashlib.sha256
    ).hexdigest()
    assert not a.verify(token, "principal", "publisher", {"actions": sorted(ROLES["publisher"])})
    other = LocalRehearsalIdentity(b"y" * 32, endpoint=a.endpoint, commit=a.commit, run_id=a.run_id)
    assert not other.verify(
        a.tokens["publisher"], "principal", "publisher", {"actions": sorted(ROLES["publisher"])}
    )


def test_identity_requires_possession_session_and_a_registered_producer_observation() -> None:
    a = authority()
    digest = "d" * 64
    assert not a.authenticate("publisher", "register-state", digest)
    with a.session("requester"):
        assert not a.authenticate("reviewer", "approve-recovery", digest)
    with a.session("publisher"):
        assert not a.authenticate("publisher", "register-state", digest)
        a.observe("state-read", {"record_sha256": digest})
        assert a.authenticate("publisher", "register-state", digest)
    with a.session("reviewer"):
        assert a.authenticate("reviewer", "approve-recovery", digest)
    with a.session("requester"):
        assert a.authenticate("reviewer", "honor-recovery-approval", digest)
        assert not a.authenticate("reviewer", "honor-recovery-approval", "e" * 64)
    a.revoked.add("reviewer")
    assert not a.authenticate("reviewer", "honor-recovery-approval", digest)


def test_default_production_still_rejects_reusing_the_previous_run(tmp_path: Path) -> None:
    v, args, _ = setup_revalidation(tmp_path / "governance.sqlite", target_run="111:1")
    with pytest.raises(ValueError, match="production run"):
        v.verify("new-release", **args)


def test_plan_predating_approval_consumption_is_rejected(tmp_path: Path) -> None:
    v, args, _ = setup_revalidation(tmp_path / "governance.sqlite")
    args["manifest"]["created_at"] = (NOW - timedelta(minutes=1)).isoformat()
    with pytest.raises(ValueError, match="after recovery approval"):
        v.verify("new-release", **args)


def test_lost_response_lookup_never_consumes_again_and_checks_revocation(tmp_path: Path) -> None:
    store, clock, _, _ = setup_approval(tmp_path / "governance.sqlite")
    token = store.approve("recovery-1", "approval-1", reviewer="reviewer")
    receipt = store.consume(token, actor="requester")
    assert store.recover_consumed(token, actor="requester") == receipt
    with pytest.raises(ValueError):
        store.recover_consumed(token, actor="other-requester")
    store.revoke("approval-1", reviewer="reviewer")
    with pytest.raises(ValueError):
        store.recover_consumed(token, actor="requester")


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "unit-missing",
        "native-missing",
        "fault-failed",
        "source",
        "old-run",
        "apply",
        "duplicate-consume",
        "ready",
        "state-version",
        "plan-hash",
        "empty-native",
        "empty-dr",
    ],
)
def test_day29_evidence_rejects_missing_failed_relabelled_or_unsafe_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    import json
    from xml.etree import ElementTree

    from scripts.iac import day29_evidence as module
    from scripts.iac.day28_evidence import SCENARIOS as day28_scenarios
    from scripts.iac.day28_evidence import source_digest as day28_source
    from tests.unit.iac.test_state_integrity import sample

    monkeypatch.setattr(
        module,
        "unit_baseline",
        lambda _: {"provenance": {"day27_commit": "a" * 40, "day27_run_id": "123:1"}},
    )
    expected = {
        "day29_commit": "a" * 40,
        "day29_run_id": "123:1",
        "day29_source_sha256": module.source_digest(),
    }

    def document(
        name: str, names: list[str], extra: dict[str, str] | None = None
    ) -> tuple[Any, Any, Path]:
        doc = ElementTree.Element("testsuites")
        suite = ElementTree.SubElement(doc, "testsuite")
        props = ElementTree.SubElement(suite, "properties")
        for k, v in {**expected, **({} if extra is None else extra)}.items():
            ElementTree.SubElement(props, "property", name=k, value=v)
        for case in names:
            ElementTree.SubElement(suite, "testcase", name=case)
        return doc, suite, tmp_path / name

    unit, suite, unit_path = document(
        "unit.xml",
        list(module.SCENARIOS | day28_scenarios),
        {
            "day28_commit": "a" * 40,
            "day28_run_id": "123:1",
            "day28_source_sha256": day28_source(),
        },
    )
    native, nsuite, npath = document(
        "native.xml", ["test_signed_registry_approval_and_native_release_revalidation"]
    )
    faults, fsuite, fpath = document(
        "fault.xml",
        [
            "test_process_exit_keeps_ambiguous_claim_spent_without_resuming[after-claim]",
            "test_process_exit_keeps_ambiguous_claim_spent_without_resuming[after-verified]",
            "test_two_processes_revalidate_one_receipt_with_exactly_one_verified_result",
        ],
    )
    _, record = sample()
    record.update(
        account="000000000000",
        environment="local",
        key="ota/local/terraform.tfstate",
        commit="a" * 40,
        run_id="123:1",
    )
    target = {**record, "bucket": "cv-recovered-state", "version_id": "copy-version"}
    dr = {
        "status": "passed",
        "scope": "localstack-only",
        "state_record": record,
        "recovered_state_record": target,
        "read_only_plans_preserved_state": True,
        "production_apply_enabled": False,
        "automatic_restore_active_backend": False,
    }
    for name, code in (("baseline", 0), ("injected_drift", 2), ("post_restore", 2)):
        dr[name] = {"refresh_exit": code, "normal_exit": code, "plan_sha256": {"normal": "f" * 64}}
    result: dict[str, Any] = {
        "status": "passed",
        "scope": "signed-local-identity-and-real-localstack",
        "provenance": expected,
        "source_state_record": record,
        "state_record": target,
        "dr_rehearsal": dr,
        "outcomes": {
            **{
                key: True
                for key in (
                    "revoked_approval_denied",
                    "lost_response_no_double_consume",
                    "approval_consumed_before_copy",
                    "actual_dual_plan_drift_denied",
                    "verified_request_not_replayed",
                    "consumed_receipt_revocation_enforced",
                )
            },
            "registry_race_exit_codes": [0, 23],
        },
        "joint_plan": {
            "refresh_exit": 0,
            "normal_exit": 0,
            "normal_binary_sha256": "b" * 64,
            "normal_json_sha256": "c" * 64,
            "refresh_json_sha256": "d" * 64,
        },
        "result": {
            "status": "VERIFIED",
            "apply_authorized": False,
            "new_release_approval_required": True,
            "production_identity_verified": False,
            "cross_runner_coordination_verified": False,
        },
        "consumptions": 1,
        "production_apply_enabled": False,
        "aws_sts_verified": False,
        "github_identity_verified": False,
        "independent_human_approval_exercised": False,
        "cross_runner_coordination_verified": False,
    }
    if mutation == "unit-missing":
        suite.remove(suite[-1])
    if mutation == "native-missing":
        nsuite.remove(nsuite[-1])
    if mutation == "fault-failed":
        ElementTree.SubElement(fsuite[-1], "failure")
    if mutation == "source":
        result["provenance"] = {**expected, "day29_source_sha256": "e" * 64}
    if mutation == "old-run":
        result["source_state_record"]["run_id"] = "999:1"
    if mutation == "apply":
        result["production_apply_enabled"] = True
    if mutation == "duplicate-consume":
        result["consumptions"] = 2
    if mutation == "ready":
        result["result"]["status"] = "READY"
    if mutation == "state-version":
        del result["state_record"]["version_id"]
    if mutation == "plan-hash":
        del result["joint_plan"]["normal_binary_sha256"]
    if mutation == "empty-native":
        result = {}
    if mutation == "empty-dr":
        result["dr_rehearsal"] = {}
    for doc, path in ((unit, unit_path), (native, npath), (faults, fpath)):
        ElementTree.ElementTree(doc).write(path)
    report = tmp_path / "native.json"
    report.write_text(json.dumps(result), encoding="utf-8")
    if mutation == "none":
        assert module.evidence(unit_path, npath, report, fpath)["apply_authorized"] is False
    else:
        with pytest.raises(ValueError):
            module.evidence(unit_path, npath, report, fpath)
