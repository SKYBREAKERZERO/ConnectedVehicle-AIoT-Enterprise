"""Verify real test outputs before writing sanitized Day28 governance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts.iac.day27_evidence import evidence as day27_evidence
from scripts.iac.day27_evidence import fault_evidence
from scripts.iac.deploy_governance import ROOT
from scripts.iac.state_integrity import validate_record

SCENARIOS = {
    "test_local_marker_cannot_authorize_a_production_record",
    "test_payload_lineage_and_serial_must_match_the_trusted_record",
    "test_reviewed_state_integrity_passes_without_granting_restore",
    "test_changed_state_identity_or_version_is_denied",
    "test_missing_corrupt_or_duplicate_state_is_denied",
    "test_hash_alone_cannot_replace_trusted_version_authority",
    "test_only_reviewed_isolated_recovery_copy_is_admissible",
    "test_recovery_never_auto_restores_active_or_unreviewed_state",
    "test_clean_and_two_distinct_drift_classes",
    "test_failed_or_inconsistent_plans_fail_closed",
    "test_refresh_only_cannot_clear_a_configuration_plan_difference",
    "test_matching_release_state_and_actual_resource_reconcile_for_review",
    "test_reconciliation_blocks_ambiguous_or_stale_releases",
    "test_day28_evidence_rejects_missing_failed_or_relabelled_proofs",
}


def source_digest() -> str:
    paths = [
        ROOT / p
        for p in (
            "scripts/iac/state_integrity.py",
            "scripts/iac/drift_policy.py",
            "scripts/iac/state_dr_probe.py",
            "scripts/iac/day28_evidence.py",
            "scripts/iac/gate.py",
            "scripts/iac/day27_evidence.py",
            "tests/unit/iac/test_state_integrity.py",
            "tests/unit/iac/test_drift_policy.py",
            "tests/integration/iac/test_state_disaster_recovery.py",
            ".github/workflows/ci.yml",
        )
    ]
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def evidence(unit_xml: Path, dr_xml: Path, dr_json: Path) -> dict[str, Any]:
    base = day27_evidence(unit_xml)
    expected = {
        "day28_commit": base["provenance"]["day27_commit"],
        "day28_run_id": base["provenance"]["day27_run_id"],
        "day28_source_sha256": source_digest(),
    }
    unit = ElementTree.fromstring(unit_xml.read_bytes())
    props = {
        p.attrib["name"]: p.attrib["value"]
        for p in unit.findall(".//testsuite/properties/property")
    }
    if any(props.get(k) != v for k, v in expected.items()):
        raise ValueError("Day28 unit source/run attestation mismatch")
    cases = [
        c.attrib["name"]
        for c in unit.findall(".//testcase")
        if c.attrib["name"].split("[", 1)[0] in SCENARIOS
    ]
    if {c.split("[", 1)[0] for c in cases} != SCENARIOS or len(cases) != len(set(cases)):
        raise ValueError("Day28 policy scenarios missing or duplicated")
    raw = dr_xml.read_bytes()
    if len(raw) > 100_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("invalid DR XML")
    doc = ElementTree.fromstring(raw)
    if doc.tag not in {"testsuites", "testsuite"} or any(
        doc.findall(".//" + tag) for tag in ("failure", "error", "skipped")
    ):
        raise ValueError("DR test not passed")
    if any(
        int(s.attrib.get(k, "0")) != 0
        for s in doc.iter()
        if s.tag in {"testsuite", "testsuites"}
        for k in ("failures", "errors", "skipped")
    ):
        raise ValueError("DR test counters not passed")
    dr_cases = doc.findall(".//testcase")
    if (
        len(dr_cases) != 1
        or dr_cases[0].attrib.get("name") != "test_versioned_state_recovery_and_both_drift_plans"
    ):
        raise ValueError("DR case missing or duplicated")
    properties = doc.findall(".//testsuite/properties/property")
    proof = {p.attrib["name"]: p.attrib["value"] for p in properties}
    if proof != expected or len(properties) != len(proof):
        raise ValueError("DR source/run attestation mismatch")
    result = json.loads(dr_json.read_bytes())
    required = (
        "corrupt_state_denied",
        "missing_state_denied",
        "pinned_version_restored_to_isolated_copy",
        "read_only_plans_preserved_state",
        "resource_drift_not_repaired",
        "interrupted_release_denied",
        "new_request_and_approval_required",
    )
    if (
        result.get("provenance") != expected
        or result.get("status") != "passed"
        or result.get("scope") != "localstack-only"
        or any(result.get(k) is not True for k in required)
        or any(
            result.get(k) is not False
            for k in (
                "aws_verified",
                "production_apply_enabled",
                "automatic_restore_active_backend",
                "automatic_force_unlock",
                "independent_human_approval_exercised",
            )
        )
    ):
        raise ValueError("DR result incomplete, relabelled or unsafe")
    for name, code, decision in (
        ("baseline", 0, "CLEAR"),
        ("injected_drift", 2, "REVIEW_REQUIRED"),
        ("post_restore", 2, "REVIEW_REQUIRED"),
    ):
        plan = result[name]
        if (
            plan["refresh_exit"] != code
            or plan["normal_exit"] != code
            or plan["classification"]["decision"] != decision
        ):
            raise ValueError("DR plan evidence contradicts fault scenario")
        classification = plan["classification"]
        if classification.get("state_drift") is not (code == 2) or classification.get(
            "configuration_drift"
        ) is not (code == 2):
            raise ValueError("Both drift dimensions must match the tested scenario")
        if (
            classification.get("automatic_remediation") is not False
            or classification.get("production_apply_enabled") is not False
            or classification.get("new_review_required") is not True
        ):
            raise ValueError("DR classification cannot grant deployment/remediation")
        if set(plan.get("plan_sha256", {})) != {"refresh", "normal"} or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None for value in plan["plan_sha256"].values()
        ):
            raise ValueError("both saved-plan digests required")
    original, recovered = result["state_record"], result["recovered_state_record"]
    validate_record(original)
    validate_record(recovered)
    if original["bucket"] == recovered["bucket"] or any(
        original[k] != recovered[k]
        for k in (
            "sha256",
            "lineage",
            "serial",
            "commit",
            "run_id",
            "environment",
            "account",
            "key",
        )
    ):
        raise ValueError("Recovery destination/version-content evidence mismatch")
    if (
        original["commit"] != expected["day28_commit"]
        or original["run_id"] != expected["day28_run_id"]
    ):
        raise ValueError("State record belongs to another CI run")
    return {
        "version": 1,
        "mode": "offline-policy-and-localstack-dr",
        "provenance": expected,
        "policy_test_cases": len(cases),
        "policy_scenarios": sorted(SCENARIOS),
        "unit_junit_sha256": hashlib.sha256(unit_xml.read_bytes()).hexdigest(),
        "dr_junit_sha256": hashlib.sha256(raw).hexdigest(),
        "dr_report_sha256": hashlib.sha256(dr_json.read_bytes()).hexdigest(),
        "state_record": original,
        "recovered_state_record": recovered,
        "production_apply_enabled": False,
        "aws_credentials_requested": False,
        "aws_dr_verified": False,
        "independent_human_recovery_approval_exercised": False,
        "deployment_admitted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.parse_args()
    folder = ROOT / ".iac-reports"
    report = evidence(
        folder / "day25-security.xml", folder / "day28-dr.xml", folder / "day28-dr.json"
    )
    # Recheck the complete Day27 fault proof before accepting the next stage.
    day27 = day27_evidence(folder / "day25-security.xml")
    fault_evidence(folder / "day27-lock.xml", folder / "day27-lock.json", day27["provenance"])
    (folder / "day28-governance.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Day28 state integrity, drift and isolated recovery evidence PASS; no deployment admitted"
    )


if __name__ == "__main__":
    main()
