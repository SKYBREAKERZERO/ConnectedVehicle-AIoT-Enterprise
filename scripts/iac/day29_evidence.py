"""Verify Day29 unit and native proofs; no production deployment authority."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts.iac.day27_evidence import evidence as unit_baseline
from scripts.iac.day28_evidence import SCENARIOS as DAY28_SCENARIOS
from scripts.iac.day28_evidence import evidence as day28_evidence
from scripts.iac.day28_evidence import source_digest as day28_source
from scripts.iac.deploy_governance import ROOT
from scripts.iac.state_integrity import validate_record

SCENARIOS = {
    "test_allowlist_still_denies_unknown_publisher_even_if_adapter_says_true",
    "test_approval_content_substitution_is_denied_without_consuming",
    "test_approval_single_consumption_is_persistent_and_does_not_execute_recovery",
    "test_business_database_and_silent_policy_changes_are_rejected",
    "test_default_production_still_rejects_reusing_the_previous_run",
    "test_drift_attestation_binds_the_actual_new_plan_and_fails_closed",
    "test_drift_or_unreliable_dual_plan_prohibits_verified",
    "test_fresh_registered_recovery_can_only_reach_verified_not_apply",
    "test_head_progression_is_monotonic_and_revocation_never_falls_back",
    "test_identity_requires_possession_session_and_a_registered_producer_observation",
    "test_inconsistent_stored_record_is_not_authenticated",
    "test_interrupted_id_and_receipt_reuse_cannot_create_another_verified_request",
    "test_invalid_approval_or_source_cannot_be_consumed",
    "test_local_credentials_reject_tampering_and_scope_changes",
    "test_lost_response_lookup_never_consumes_again_and_checks_revocation",
    "test_matching_hash_with_an_unregistered_version_is_rejected",
    "test_plan_predating_approval_consumption_is_rejected",
    "test_registered_head_survives_reopen_and_scope_return_is_not_mutable_policy",
    "test_registry_rejects_cross_scope_or_substituted_metadata",
    "test_registry_rejects_reset_and_immutable_version_replacement",
    "test_rehearsal_never_relaxes_the_default_production_contract",
    "test_request_and_target_replacement_or_reapproval_are_denied",
    "test_revocation_and_expiry_invalidate_an_already_consumed_receipt",
    "test_revocation_between_initial_check_and_day27_commit_is_rechecked",
    "test_revoked_authorities_block_release_verification",
    "test_self_review_or_unlisted_reviewer_is_denied",
    "test_signed_but_expired_credential_and_issuer_key_mismatch_are_denied",
    "test_stale_or_substituted_revalidation_inputs_are_rejected",
    "test_two_processes_can_adopt_only_one_approval",
    "test_unverified_publisher_cannot_register",
    "test_day29_evidence_rejects_missing_failed_relabelled_or_unsafe_reports",
}


def xml_proof(path: Path) -> tuple[ElementTree.Element, dict[str, str]]:
    raw = path.read_bytes()
    if len(raw) > 2_000_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("invalid Day29 XML")
    doc = ElementTree.fromstring(raw)
    if doc.tag not in {"testsuite", "testsuites"} or any(
        doc.findall(".//" + tag) for tag in ("failure", "error", "skipped")
    ):
        raise ValueError("Day29 tests failed/skipped")
    if any(
        int(s.attrib.get(k, "0")) != 0
        for s in doc.iter()
        if s.tag in {"testsuite", "testsuites"}
        for k in ("failures", "errors", "skipped")
    ):
        raise ValueError("Day29 counters failed/skipped")
    properties = doc.findall(".//properties/property")
    props = {p.attrib["name"]: p.attrib["value"] for p in properties}
    if len(props) != len(properties):
        raise ValueError("duplicate test-time provenance")
    return doc, props


def cases(doc: ElementTree.Element, names: set[str]) -> list[str]:
    selected = [
        c.attrib["name"]
        for c in doc.findall(".//testcase")
        if c.attrib["name"].split("[", 1)[0] in names
    ]
    if {c.split("[", 1)[0] for c in selected} != names or len(selected) != len(set(selected)):
        raise ValueError("mandatory cases missing/duplicated")
    return selected


def source_digest() -> str:
    names = [
        "scripts/iac/" + name + ".py"
        for name in (
            "trusted_state_registry",
            "recovery_approval",
            "release_revalidation",
            "local_rehearsal_identity",
            "day29_native_probe",
            "day29_evidence",
            "plan_admission",
            "release_admission",
            "state_dr_probe",
            "gate",
        )
    ]
    names += [
        "tests/unit/iac/" + name + ".py"
        for name in (
            "test_trusted_state_registry",
            "test_recovery_approval",
            "test_release_revalidation",
            "test_day29_rehearsal_contracts",
        )
    ]
    names += [
        "tests/integration/iac/test_day29_native_recovery.py",
        "tests/integration/iac/test_day29_process_faults.py",
        ".github/workflows/ci.yml",
        ".github/workflows/ota-aws-deploy.yml",
    ]
    digest = hashlib.sha256()
    for name in sorted(names):
        digest.update(name.encode() + b"\0")
        digest.update((ROOT / name).read_bytes())
    return digest.hexdigest()


def evidence(unit: Path, native_xml: Path, native_json: Path, fault_xml: Path) -> dict[str, Any]:
    baseline = unit_baseline(unit)
    expected = {
        "day29_commit": baseline["provenance"]["day27_commit"],
        "day29_run_id": baseline["provenance"]["day27_run_id"],
        "day29_source_sha256": source_digest(),
    }
    doc, props = xml_proof(unit)
    if any(props.get(k) != v for k, v in expected.items()):
        raise ValueError("Day29 unit source/run mismatch")
    if any(
        props.get(k) != v
        for k, v in {
            "day28_commit": expected["day29_commit"],
            "day28_run_id": expected["day29_run_id"],
            "day28_source_sha256": day28_source(),
        }.items()
    ):
        raise ValueError("Day28 unit proof mismatch")
    cases(doc, DAY28_SCENARIOS)
    security = cases(doc, SCENARIOS)
    native, nprops = xml_proof(native_xml)
    faults, fprops = xml_proof(fault_xml)
    if nprops != expected or fprops != expected:
        raise ValueError("native/fault source/run mismatch")
    native_cases = cases(native, {"test_signed_registry_approval_and_native_release_revalidation"})
    fault_cases = cases(
        faults,
        {
            "test_process_exit_keeps_ambiguous_claim_spent_without_resuming",
            "test_two_processes_revalidate_one_receipt_with_exactly_one_verified_result",
        },
    )
    if (
        len(native_cases) != 1
        or len(native.findall(".//testcase")) != 1
        or len(fault_cases) != 3
        or len(faults.findall(".//testcase")) != 3
    ):
        raise ValueError("native/fault cases incomplete")
    raw = native_json.read_bytes()
    if len(raw) > 500_000:
        raise ValueError("native report oversized")
    result = json.loads(raw)
    fields = {
        "status",
        "scope",
        "outcomes",
        "state_record",
        "source_state_record",
        "dr_rehearsal",
        "joint_plan",
        "result",
        "consumptions",
        "production_apply_enabled",
        "aws_sts_verified",
        "github_identity_verified",
        "independent_human_approval_exercised",
        "cross_runner_coordination_verified",
        "provenance",
    }
    if (
        set(result) != fields
        or result["status"] != "passed"
        or result["scope"] != "signed-local-identity-and-real-localstack"
        or result["provenance"] != expected
    ):
        raise ValueError("native report incomplete or relabelled")
    if any(
        result[k] is not False
        for k in (
            "production_apply_enabled",
            "aws_sts_verified",
            "github_identity_verified",
            "independent_human_approval_exercised",
            "cross_runner_coordination_verified",
        )
    ):
        raise ValueError("local rehearsal cannot claim production identity/deployment")
    outcomes = result["outcomes"]
    required = {
        "revoked_approval_denied",
        "lost_response_no_double_consume",
        "approval_consumed_before_copy",
        "actual_dual_plan_drift_denied",
        "verified_request_not_replayed",
        "consumed_receipt_revocation_enforced",
    }
    if any(outcomes.get(k) is not True for k in required) or sorted(
        outcomes.get("registry_race_exit_codes", [])
    ) != [0, 23]:
        raise ValueError("fault outcome missing or unsafe")
    if result["consumptions"] != 1 or type(result["consumptions"]) is not int:
        raise ValueError("approval consumed more than once")
    accepted = result["result"]
    if (
        accepted.get("status") != "VERIFIED"
        or accepted.get("apply_authorized") is not False
        or accepted.get("new_release_approval_required") is not True
        or accepted.get("production_identity_verified") is not False
        or accepted.get("cross_runner_coordination_verified") is not False
    ):
        raise ValueError("revalidation cannot grant Apply/READY")
    source, target = result["source_state_record"], result["state_record"]
    validate_record(source)
    validate_record(target)
    if source["bucket"] == target["bucket"] or any(
        source[k] != target[k]
        for k in (
            "account",
            "environment",
            "sha256",
            "lineage",
            "serial",
            "commit",
            "run_id",
            "key",
        )
    ):
        raise ValueError("registered source/target mismatch")
    if (
        source["account"] != "000000000000"
        or source["environment"] != "local"
        or source["commit"] != expected["day29_commit"]
        or source["run_id"] != expected["day29_run_id"]
    ):
        raise ValueError("rehearsal scope or actual CI state identity mismatch")
    dr = result["dr_rehearsal"]
    if (
        dr.get("status") != "passed"
        or dr.get("scope") != "localstack-only"
        or dr.get("state_record") != source
        or dr.get("recovered_state_record") != target
        or dr.get("read_only_plans_preserved_state") is not True
        or dr.get("production_apply_enabled") is not False
        or dr.get("automatic_restore_active_backend") is not False
    ):
        raise ValueError("underlying native DR proof incomplete")
    for name, code in (("baseline", 0), ("injected_drift", 2), ("post_restore", 2)):
        if (
            dr.get(name, {}).get("refresh_exit") != code
            or dr.get(name, {}).get("normal_exit") != code
        ):
            raise ValueError("native drift sequence missing")
    pair = result["joint_plan"]
    if pair.get("refresh_exit") != 0 or pair.get("normal_exit") != 0:
        raise ValueError("native joint plan not clear")
    import re

    if any(
        re.fullmatch(r"[0-9a-f]{64}", pair.get(k, "")) is None
        for k in ("normal_binary_sha256", "normal_json_sha256", "refresh_json_sha256")
    ):
        raise ValueError("saved-plan proof missing")
    if pair["normal_binary_sha256"] == dr.get("baseline", {}).get("plan_sha256", {}).get("normal"):
        raise ValueError("old native saved plan reused")
    return {
        "version": 1,
        "mode": "localstack-native-and-local-process-faults",
        "provenance": expected,
        "unit_security_cases": len(security),
        "mandatory_unit_scenarios": sorted(SCENARIOS),
        "native_cases": 1,
        "process_fault_cases": 3,
        "unit_junit_sha256": hashlib.sha256(unit.read_bytes()).hexdigest(),
        "native_junit_sha256": hashlib.sha256(native_xml.read_bytes()).hexdigest(),
        "process_junit_sha256": hashlib.sha256(fault_xml.read_bytes()).hexdigest(),
        "native_report_sha256": hashlib.sha256(raw).hexdigest(),
        "source_state_record": source,
        "recovered_state_record": target,
        "joint_plan": pair,
        "release_status": "VERIFIED",
        "apply_authorized": False,
        "production_identity_verified": False,
        "github_approval_exercised": False,
        "cross_runner_coordination_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.parse_args()
    folder = ROOT / ".iac-reports"
    day28_evidence(folder / "day25-security.xml", folder / "day28-dr.xml", folder / "day28-dr.json")
    report = evidence(
        folder / "day25-security.xml",
        folder / "day29-native.xml",
        folder / "day29-native.json",
        folder / "day29-faults.xml",
    )
    (folder / "day29-governance.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Day29 native registry/recovery/revalidation and fault Evidence PASS; Apply stays disabled"
    )


if __name__ == "__main__":
    main()
