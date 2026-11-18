"""Fail-closed Day30 local failure-isolation evidence; never release authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.iac.day29_evidence import cases, xml_proof
from scripts.iac.day29_evidence import evidence as day29_evidence
from scripts.iac.deploy_governance import ROOT, run_identity

SCENARIOS = {
    "test_crash_after_day27_verified_is_quarantined",
    "test_two_reconcilers_create_one_quarantine",
    "test_quarantine_blocks_release_admission",
    "test_quarantine_does_not_affect_other_release",
    "test_unknown_commit_result_never_reuses_approval",
    "test_reconciliation_never_promotes_to_ready",
}
ENTRIES = {
    "request",
    "state",
    "VERIFIED",
    "APPROVED",
    "READY",
    "interrupt",
    "revalidate",
    "receipt",
    "lookup",
}


def source_digest() -> str:
    files = [
        "scripts/iac/" + n + ".py"
        for n in (
            "failure_isolation",
            "release_admission",
            "release_revalidation",
            "recovery_approval",
            "trusted_state_registry",
            "day30_evidence",
            "gate",
        )
    ]
    files += [
        "tests/unit/iac/test_failure_isolation.py",
        "tests/integration/iac/test_day30_failure_isolation.py",
        ".github/workflows/ci.yml",
        ".github/workflows/ota-aws-deploy.yml",
    ]
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode() + b"\0")
        h.update((ROOT / name).read_bytes())
    return h.hexdigest()


def provenance() -> dict[str, str]:
    return {
        "day30_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day30_run_id": run_identity(),
        "day30_source_sha256": source_digest(),
    }


def fault_evidence(xml: Path, report: Path, expected: dict[str, str]) -> dict[str, Any]:
    doc, props = xml_proof(xml)
    selected = cases(doc, SCENARIOS)
    if props != expected or len(selected) != 6 or len(doc.findall(".//testcase")) != 6:
        raise ValueError("Day30 missing/duplicated/cross-run fault proof")
    raw = report.read_bytes()
    if len(raw) > 100_000:
        raise ValueError("Day30 report too large")
    data = json.loads(raw)
    if set(data) != {"provenance", "scenarios"} or data["provenance"] != expected:
        raise ValueError("Day30 report source/run mismatch")
    s = data["scenarios"]
    if set(s) != {"crash", "race", "admission", "isolation", "unknown", "reconciliation"}:
        raise ValueError("Day30 missing measured scenarios")
    required = {
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
    # Strict types, no true-as-1 substitution or extra unreviewed safety claims.
    if json.dumps(s, sort_keys=True) != json.dumps(required, sort_keys=True):
        raise ValueError("Day30 measured isolation did not meet acceptance")
    return {
        "provenance": expected,
        "fault_cases": len(selected),
        "fault_junit_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
        "fault_report_sha256": hashlib.sha256(raw).hexdigest(),
        "failure_isolation": {
            "quarantine_atomic": s["crash"]["audit_matches"] == s["crash"]["quarantines"]
            and s["crash"]["audit_failure_rollback_counts"] == [0, 0],
            "duplicate_quarantine_count": s["race"]["quarantines"] - s["race"]["unique_operations"],
            "unrelated_release_affected": not s["isolation"]["failed_release_preserved"]
            or s["isolation"]["unrelated_state"] != "VERIFIED",
            "approval_reconsumed": s["unknown"]["consumptions"] != 1
            or s["unknown"]["consumption_audits"] != 1,
            "automatic_promotion": not s["reconciliation"]["original_rows_preserved"],
            "admission_entries_denied": len(s["admission"]["denied"]),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.parse_args()
    p = ROOT / ".iac-reports"
    previous = day29_evidence(
        p / "day25-security.xml",
        p / "day29-native.xml",
        p / "day29-native.json",
        p / "day29-faults.xml",
    )
    expected = provenance()
    if (
        previous["provenance"]["day29_commit"] != expected["day30_commit"]
        or previous["provenance"]["day29_run_id"] != expected["day30_run_id"]
    ):
        raise ValueError("Day29/30 provenance differs")
    doc, props = xml_proof(p / "day25-security.xml")
    unit_cases = cases(
        doc,
        {
            "test_locked_transaction_is_bounded_and_does_not_retry_adoption",
            "test_state_head_change_only_invalidates_exact_related_bindings",
            "test_bad_preflight_isolates_only_authenticated_unowned_request",
            "test_losing_request_cannot_quarantine_completed_winner",
            "test_default_cli_scan_does_not_even_create_isolation_tables",
            "test_evidence_rejects_incomplete_replayed_or_ineffective_isolation",
        },
    )
    if previous != json.loads((p / "day29-governance.json").read_text(encoding="utf-8")):
        raise ValueError("Day29 stored proof differs from verified result")
    if any(props.get(k) != v for k, v in expected.items()):
        raise ValueError("Day30 unit proof missing or stale")
    result = fault_evidence(p / "day30-faults.xml", p / "day30-faults.json", expected)
    result["unit_security_cases"] = len(unit_cases)
    result["failure_isolation"]["production_apply_enabled"] = previous["apply_authorized"]
    result.update(
        scope="local-sqlite-process-faults-only",
        unit_junit_sha256=hashlib.sha256((p / "day25-security.xml").read_bytes()).hexdigest(),
        previous_evidence_sha256=hashlib.sha256(
            (p / "day29-governance.json").read_bytes()
        ).hexdigest(),
    )
    (p / "day30-governance.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print("Day30 failure isolation Evidence PASS; no promotion or production Apply")


if __name__ == "__main__":
    main()
