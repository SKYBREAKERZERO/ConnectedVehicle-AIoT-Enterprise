"""Produce sanitized offline governance evidence; never upload a binary plan or state."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from scripts.iac.deploy_governance import ROOT, static_evidence

SCENARIOS = {
    "test_bound_saved_plan_contract_passes",
    "test_wrong_or_expired_plan_rejected",
    "test_saved_plan_bytes_cannot_change",
    "test_approval_cannot_be_reused_or_self_approved",
    "test_replay_reservation_survives_restart_and_relabel",
    "test_concurrent_replay_has_one_winner",
    "test_main_rules_require_independent_review",
    "test_no_cloud_credentials_apply_or_plan_upload",
    "test_manifest_schema_is_closed",
    "test_day26_evidence_rejects_relabel_or_missing_scenario",
    "test_dry_run_rechecks_live_main_rules",
    "test_s3_probe_rejects_real_endpoints_before_client_creation",
}


def source_digest() -> str:
    paths = [
        ROOT / p
        for p in (
            "scripts/iac/plan_admission.py",
            "scripts/iac/gate.py",
            "scripts/iac/state_lock_probe.py",
            "scripts/iac/day26_evidence.py",
            "tests/unit/iac/test_plan_admission.py",
            ".github/workflows/ci.yml",
            ".github/workflows/ota-aws-deploy.yml",
            "infra/terraform/environments/ota-aws/backend.tf.example",
        )
    ]
    paths.extend((ROOT / "infra/terraform/modules/terraform-state-store").rglob("*.tf"))
    paths.extend((ROOT / "infra/terraform/modules/terraform-state-store").rglob("*.tftest.hcl"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def evidence(xml: Path) -> dict[str, Any]:
    # Reuse the fail-closed full-suite parser and test-time Day25 provenance.
    day25 = static_evidence(xml)
    document = ElementTree.fromstring(xml.read_bytes())
    props = {
        p.attrib["name"]: p.attrib["value"]
        for p in document.findall(".//testsuite/properties/property")
    }
    expected = {
        "day26_commit": day25["provenance"]["commit"],
        "day26_run_id": day25["provenance"]["run_id"],
        "day26_source_sha256": source_digest(),
    }
    if any(props.get(key) != value for key, value in expected.items()):
        raise ValueError("Day26 test-time source/run attestation mismatch")
    cases = [
        case.attrib["name"]
        for case in document.findall(".//testcase")
        if case.attrib["name"].split("[", 1)[0] in SCENARIOS
    ]
    if {case.split("[", 1)[0] for case in cases} != SCENARIOS or len(cases) != len(set(cases)):
        raise ValueError("Day26 mandatory scenarios missing or duplicated")
    return {
        "version": 1,
        "mode": "offline-contracts",
        "environment": "production",
        "provenance": expected,
        "junit_sha256": day25["junit_sha256"],
        "scenarios": sorted(SCENARIOS),
        "security_test_cases": len(cases),
        "production_apply_enabled": False,
        "aws_credentials_requested": False,
        "aws_s3_lock_contention_verified": False,
        "aws_sts_verified": False,
        "production_replay_ledger_verified": False,
        "github_independent_approval_exercised": False,
    }


def main() -> None:
    report = evidence(ROOT / ".iac-reports/day25-security.xml")
    path = ROOT / ".iac-reports/day26-governance.json"
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Day26 offline security contracts PASS; no production deployment authorized")


if __name__ == "__main__":
    main()
