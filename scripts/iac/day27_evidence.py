"""Sanitized Day27 offline admission + emulator fault evidence, never authorization."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts.iac.day26_evidence import evidence as day26_evidence
from scripts.iac.deploy_governance import ROOT

SCENARIOS = {
    "test_ordered_admission_is_persistent_and_ready_is_one_shot",
    "test_states_cannot_skip_verification_or_approval",
    "test_post_approval_trusted_context_change_rejected",
    "test_post_approval_plan_source_or_evidence_change_rejected",
    "test_old_foreign_or_tampered_evidence_denied",
    "test_approval_rechecked_and_failures_persist",
    "test_new_request_cannot_reuse_old_request_approval",
    "test_same_backend_concurrent_requests_have_one_ready_winner",
    "test_crash_after_ready_never_resumes_or_releases_reservation",
    "test_expired_or_revoked_evidence_cannot_reach_ready",
    "test_evidence_cannot_move_to_a_new_request",
    "test_recovery_never_unlocks_deletes_or_resumes",
    "test_recovery_rejects_unknown_or_truthy_observations",
    "test_day27_report_rejects_relabel_or_missing_scenarios",
    "test_fault_report_cannot_be_relabelled_or_hide_unsafe_recovery",
}


def source_digest() -> str:
    paths = [
        ROOT / p
        for p in (
            "scripts/iac/release_admission.py",
            "scripts/iac/state_recovery_policy.py",
            "scripts/iac/state_failure_probe.py",
            "scripts/iac/day27_evidence.py",
            "scripts/iac/plan_admission.py",
            "scripts/iac/gate.py",
            "scripts/iac/deploy_governance.py",
            "tests/unit/iac/test_release_admission.py",
            "tests/unit/iac/test_state_recovery_policy.py",
            "tests/unit/iac/test_plan_admission.py",
            "tests/integration/iac/test_state_lock_contention.py",
            ".github/workflows/ci.yml",
            ".github/workflows/ota-aws-deploy.yml",
        )
    ]
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def evidence(xml: Path) -> dict[str, Any]:
    base = day26_evidence(xml)
    document = ElementTree.fromstring(xml.read_bytes())
    props = {
        p.attrib["name"]: p.attrib["value"]
        for p in document.findall(".//testsuite/properties/property")
    }
    expected = {
        "day27_commit": base["provenance"]["day26_commit"],
        "day27_run_id": base["provenance"]["day26_run_id"],
        "day27_source_sha256": source_digest(),
    }
    if any(props.get(key) != value for key, value in expected.items()):
        raise ValueError("Day27 test-time source/run attestation mismatch")
    cases = [
        c.attrib["name"]
        for c in document.findall(".//testcase")
        if c.attrib["name"].split("[", 1)[0] in SCENARIOS
    ]
    if {case.split("[", 1)[0] for case in cases} != SCENARIOS or len(cases) != len(set(cases)):
        raise ValueError("Day27 mandatory scenarios missing or duplicated")
    return {
        "version": 1,
        "mode": "offline-admission-contracts",
        "environment": "production",
        "provenance": expected,
        "scenarios": sorted(SCENARIOS),
        "security_test_cases": len(cases),
        "junit_sha256": base["junit_sha256"],
        "production_apply_enabled": False,
        "aws_credentials_requested": False,
        "aws_s3_fault_recovery_verified": False,
        "authenticated_production_authority_verified": False,
        "cross_runner_ledger_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-fault", action="store_true")
    args = parser.parse_args()
    report = evidence(ROOT / ".iac-reports/day25-security.xml")
    if args.with_fault:
        report["fault_injection"] = fault_evidence(
            ROOT / ".iac-reports/day27-lock.xml",
            ROOT / ".iac-reports/day27-lock.json",
            report["provenance"],
        )
    (ROOT / ".iac-reports/day27-governance.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print("Day27 offline admission/recovery contracts PASS; production Apply remains disabled")


def fault_evidence(xml: Path, result_path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    raw = xml.read_bytes()
    if len(raw) > 100_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("invalid fault XML")
    doc = ElementTree.fromstring(raw)
    if doc.tag not in {"testsuites", "testsuite"}:
        raise ValueError("invalid fault XML root")
    if any(doc.findall(".//" + tag) for tag in ("failure", "error", "skipped")):
        raise ValueError("fault test not passed")
    if any(
        int(s.attrib.get(k, "0")) != 0
        for s in doc.iter()
        if s.tag in {"testsuite", "testsuites"}
        for k in ("failures", "errors", "skipped")
    ):
        raise ValueError("fault test counters not passed")
    cases = doc.findall(".//testcase")
    if (
        len(cases) != 1
        or cases[0].attrib.get("name") != "test_native_lock_survives_holder_process_termination"
    ):
        raise ValueError("fault case missing or duplicated")
    properties = doc.findall(".//testsuite/properties/property")
    props = {p.attrib["name"]: p.attrib["value"] for p in properties}
    if props != expected or len(props) != len(properties):
        raise ValueError("fault test source/run mismatch")
    result = json.loads(result_path.read_bytes())
    if (
        result.get("provenance") != expected
        or result.get("status") != "passed"
        or any(
            result.get(k) is not True
            for k in (
                "localstack_only",
                "holder_process_killed",
                "orphan_lock_retained",
                "state_unchanged",
            )
        )
        or any(
            result.get(k) is not False
            for k in ("aws_verified", "automatic_force_unlock", "apply_performed")
        )
    ):
        raise ValueError("fault report incomplete or unsafe")
    return {
        "status": "passed",
        "scope": "localstack-native-terraform-process-kill",
        "junit_sha256": hashlib.sha256(raw).hexdigest(),
        "report_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "provenance": expected,
        "aws_verified": False,
    }


if __name__ == "__main__":
    main()
