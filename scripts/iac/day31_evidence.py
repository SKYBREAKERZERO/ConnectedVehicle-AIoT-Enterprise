"""Day31 mandatory-flow evidence and event-bound workflow provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from scripts.iac.workflow_evidence_binding import SOURCE_FILES, digest_sources

ROOT = Path(__file__).resolve().parents[2]
UNIT_CASES = {
    *(f"test_baseline_attack_flows_fail_closed[F0{i}]" for i in range(1, 5)),
    *(f"test_workflow_identity_attack_flows_are_denied[{i}]" for i in ("F05", "F06", "F12")),
    "test_day31_evidence_refuses_missing_and_replayed_flow_proof[F11]",
}
FAULT_CASES = {
    "test_real_git_merge_graph_binds_baseline_to_event",
    "test_partial_commit_and_reconciled_replay_are_blocked",
    "test_unknown_commit_race_and_bounded_lock_never_reconsume",
    *(
        f"test_revocation_and_admission_serialize_without_post_revoke_promotion[{o}]"
        for o in ("admission-first", "revoke-first")
    ),
}


def source_digest() -> str:
    return digest_sources({n: (ROOT / n).read_bytes() for n in SOURCE_FILES})


def provenance(prefix: str = "day31") -> dict[str, str]:
    return {
        prefix + "_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        prefix + "_run_id": os.environ.get("GITHUB_RUN_ID", "local")
        + ":"
        + os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        prefix + "_source_sha256": source_digest(),
    }


def xml_cases(
    raw: bytes, required: set[str], expected: dict[str, str], *, exact: bool = False
) -> None:
    if len(raw) > 3_000_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("invalid bounded XML")
    root = ET.fromstring(raw)
    if root.tag not in {"testsuite", "testsuites"} or any(
        root.findall(".//" + tag) for tag in ("failure", "error", "skipped")
    ):
        raise ValueError("failed/skipped test proof")
    for s in root.iter():
        if s.tag in {"testsuite", "testsuites"} and any(
            int(s.attrib.get(k, "0")) for k in ("failures", "errors", "skipped")
        ):
            raise ValueError("failed/skipped counters")
    properties = root.findall(".//properties/property")
    props = {p.attrib["name"]: p.attrib["value"] for p in properties}
    if len(props) != len(properties) or any(props.get(k) != v for k, v in expected.items()):
        raise ValueError("JUnit source/Run/Attempt mismatch")
    names = [t.attrib["name"] for t in root.findall(".//testcase")]
    selected = [name for name in names if name in required]
    if (
        not required.issubset(names)
        or len(selected) != len(set(selected))
        or (exact and set(names) != required)
    ):
        raise ValueError("mandatory fault flow absent/duplicated")


def verify_documents(
    unit: bytes, fault: bytes, facts: bytes, expected: dict[str, str]
) -> dict[str, Any]:
    xml_cases(unit, UNIT_CASES, expected)
    xml_cases(fault, FAULT_CASES, expected, exact=True)
    if len(facts) > 100_000:
        raise ValueError("fault proof too large")
    actual = json.loads(facts)
    wanted = {
        "provenance": expected,
        "isolation": {
            "crash": {
                "quarantines": 1,
                "audit_matches": 1,
                "audit_failure_rollback_counts": [0, 0],
                "original_rows_preserved": True,
            },
            "reconciled": {"original_rows_preserved": True, "reconciled_still_denied": True},
        },
        "unknown": {"consumptions": 1, "consumption_audits": 1, "commit_lookup_matches": True},
        "race": {"quarantines": 1, "audits": 1, "unique_operations": 1, "exit_codes": [0, 0]},
        "lock_consumptions": 1,
        "revocation": [
            {
                "order": o,
                "admission_exit": 0 if o == "admission-first" else 23,
                "revoke_exit": 0,
                "ready_count": 0,
                "consumptions": 1,
                "post_revoke_denied": True,
            }
            for o in ("admission-first", "revoke-first")
        ],
    }
    if json.dumps(actual, sort_keys=True) != json.dumps(wanted, sort_keys=True):
        raise ValueError("measured fault outcomes/source mismatch")
    return {
        "provenance": expected,
        "mandatory_flows": [f"F{i:02}" for i in range(1, 13)],
        "fault_cases": len(FAULT_CASES),
        "unit_junit_sha256": hashlib.sha256(unit).hexdigest(),
        "fault_junit_sha256": hashlib.sha256(fault).hexdigest(),
        "fault_report_sha256": hashlib.sha256(facts).hexdigest(),
        "apply_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--runtime", action="store_true")
    args = parser.parse_args()
    from scripts.iac.ci_baseline_policy import current

    if args.runtime:
        folder = ROOT / ".runtime-reports"
        name = "day31-runtime-baseline.json"
        raw = (folder / name).read_bytes()
        if json.loads(raw) != current():
            raise ValueError("Runtime baseline changed since verification")
        result = {
            "provenance": provenance("day31_runtime"),
            "baseline_sha256": hashlib.sha256(raw).hexdigest(),
            "apply_authorized": False,
        }
        (folder / "day31-runtime.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    else:
        folder = ROOT / ".iac-reports"
        raw = (folder / "day31-baseline.json").read_bytes()
        if json.loads(raw) != current():
            raise ValueError("IaC baseline changed since verification")
        from scripts.iac.day30_evidence import main as day30_main

        previous = (folder / "day30-governance.json").read_bytes()
        day30_main()
        if previous != (folder / "day30-governance.json").read_bytes():
            raise ValueError("Day30 evidence altered or stale")
        result = verify_documents(
            (folder / "day25-security.xml").read_bytes(),
            (folder / "day31-faults.xml").read_bytes(),
            (folder / "day31-faults.json").read_bytes(),
            provenance(),
        )
        result.update(
            baseline_sha256=hashlib.sha256(raw).hexdigest(),
            day30_evidence_sha256=hashlib.sha256(previous).hexdigest(),
            cross_workflow_binding_completed=False,
        )
        (folder / "day31-governance.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    print("Day31 candidate provenance and mandatory proof verified; no deployment authority")


if __name__ == "__main__":
    main()
