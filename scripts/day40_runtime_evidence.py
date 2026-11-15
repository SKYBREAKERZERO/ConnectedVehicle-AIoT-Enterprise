"""Day40 local runtime evidence and a separate, closed AWS decision."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.day39_ci_evidence import ROOTS, write
from scripts.iac.day31_evidence import provenance, xml_cases
from scripts.iac.pipeline_evidence import require_needs, verify

SUITES = {
    "quality": {
        "test_wrong_aws_account_stops_before_resource_calls",
        "test_audit_denial_preserves_block_without_secret_reads",
    },
    "postgres": {
        "test_actual_database_and_localstack_rotation_failure_recovery",
        "test_rejected_recovery_cannot_change_real_passwords_secrets_or_journals",
    },
    "redis": {"test_redis_tls_overlap_and_replacement"},
}
REPORTS = {
    **{suite: f"{suite}.xml" for suite in SUITES},
    **{f"terraform-{root}": "validate.json" for root in ROOTS},
    "scan": "checkov.json",
}
REQUIRED = {"intake", "quality", "postgres", "redis", "terraform", "scan", "evidence"}


def identity() -> dict[str, str]:
    facts = provenance()
    if (
        facts["day31_commit"]
        != subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    ):
        raise ValueError("Day40 checkout does not match the candidate SHA")
    return facts


def assemble(folder: Path, output: Path) -> None:
    facts = identity()
    names = {
        stage: f"day40-proof-{stage}-{facts['day31_run_id'].replace(':', '-')}" for stage in REPORTS
    }
    if {path.name for path in folder.iterdir()} != set(names.values()):
        raise ValueError("Day40 report inventory mismatch")
    digests = {}
    for stage, file in REPORTS.items():
        bundle = folder / names[stage]
        members = verify(bundle, stage)
        if set(members) != {file}:
            raise ValueError(f"Unexpected report members for {stage}")
        raw = (bundle / file).read_bytes()
        if stage in SUITES:
            xml_cases(raw, SUITES[stage], {}, exact=stage != "quality")
        elif stage == "scan":
            if json.loads(raw) != {
                "status": "passed",
                "phase": "security",
                "security_scan": "passed",
                "scanned_sources": 2,
            }:
                raise ValueError("Both Checkov targets must pass")
        else:
            validation = json.loads(raw)
            if validation.get("valid") is not True or validation.get("error_count") != 0:
                raise ValueError(f"Native validation failed for {stage}")
        digests[stage] = members[file]
    write(output, {"provenance": facts, "reports": digests})


def finalize(folder: Path, output: Path) -> int:
    facts = identity()
    needs = json.loads(os.environ["PIPELINE_NEEDS"])
    decision: dict[str, Any] = {
        "provenance": facts,
        "jobs": {name: data["result"] for name, data in needs.items()},
        "local_decision": "BLOCKED",
        "aws_staging_decision": "BLOCKED",
        "aws_rotation_verified": False,
        "release_authorized": False,
        "production_authorized": False,
        "aws_reason": "No approved AWS rotation or service continuity evidence in this PR workflow",
    }
    try:
        require_needs(REQUIRED, needs)
        members = verify(folder, "aggregate")
        if set(members) != {"aggregate.json"}:
            raise ValueError("Unexpected Day40 aggregate inventory")
        aggregate = json.loads((folder / "aggregate.json").read_bytes())
        if aggregate["provenance"] != facts or set(aggregate["reports"]) != set(REPORTS):
            raise ValueError("Day40 aggregate source or coverage mismatch")
        decision["aggregate_sha256"] = members["aggregate.json"]
        decision["local_decision"] = "ROTATION_TESTED_LOCAL"
    except (ValueError, KeyError, TypeError, OSError) as exc:
        decision["local_reason"] = str(exc)
    write(output, decision)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(f"\n**Local runtime:** `{decision['local_decision']}`\n\n")
            stream.write("**AWS Staging:** `BLOCKED`\n")
    return 0 if decision["local_decision"] == "ROTATION_TESTED_LOCAL" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "finalize"))
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "finalize":
        return finalize(args.folder, args.output)
    assemble(args.folder, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
