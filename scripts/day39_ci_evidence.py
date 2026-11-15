"""Verify Day39 CI reports and issue a non-authorizing workflow decision."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from scripts.iac.day31_evidence import provenance, xml_cases
from scripts.iac.pipeline_evidence import require_needs, verify

ROOTS = ("ota-staging", "ota-staging-foundation", "ota-staging-identity")
PRODUCERS = {"faults", "contracts", "terraform"}
REQUIRED = {"intake", "quality", "scan", "evidence", *PRODUCERS}
FAULTS = {
    "test_cross_commit_receipt_is_rejected",
    "test_older_attempt_jobs_are_rejected",
    "test_renamed_older_attempt_artifact_is_rejected",
    "test_tampered_archive_digest_is_rejected",
    "test_required_security_job_is_missing",
    "test_day37_denies_release_when_security_proof_is_missing",
    "test_green_runtime_without_sealed_security_artifact_is_rejected",
    "test_pr_modified_verifier_cannot_supply_pass[GITHUB_EVENT_NAME-pull_request]",
    "test_latest_run_blocks_even_after_older_run_is_rerun[failure]",
}


def write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def assemble(folder: Path, output: Path) -> None:
    inventory = {
        "day39-faults": "faults.xml",
        "day39-contracts": "contracts.xml",
        **{f"day39-{root}": "validate.json" for root in ROOTS},
    }
    if set(p.name for p in folder.iterdir()) != set(inventory):
        raise ValueError("Day39 stage inventory mismatch")
    hashes: dict[str, str] = {}
    for stage, name in inventory.items():
        bundle = folder / stage
        members = verify(bundle, stage)
        if set(members) != {name}:
            raise ValueError(f"Unexpected report inventory for {stage}")
        raw = (bundle / name).read_bytes()
        if name.endswith(".xml"):
            xml_cases(
                raw,
                FAULTS
                if stage == "day39-faults"
                else {"test_foundation_rds_tls_enforced_by_bound_postgres17_group"},
                {},
            )
        else:
            result = json.loads(raw)
            if result.get("valid") is not True or result.get("error_count") != 0:
                raise ValueError(f"Invalid Terraform validation for {stage}")
        hashes[stage] = members[name]
    write(output, {"provenance": provenance(), "reports": hashes})


def finalize(folder: Path, output: Path) -> int:
    needs = json.loads(os.environ["PIPELINE_NEEDS"])
    result: dict[str, Any] = {
        "provenance": provenance(),
        "jobs": {name: data["result"] for name, data in needs.items()},
        "decision": "BLOCKED",
        "aws_authorized": False,
        "production_authorized": False,
    }
    try:
        require_needs(REQUIRED, needs)
        files = verify(folder, "day39-aggregate")
        if set(files) != {"aggregate.json"}:
            raise ValueError("Missing Day39 aggregate")
        report = json.loads((folder / "aggregate.json").read_bytes())
        if report["provenance"] != result["provenance"]:
            raise ValueError("Aggregate commit or Attempt changed")
        result["aggregate_sha256"] = files["aggregate.json"]
        result["decision"] = "OFFLINE_VERIFICATION_PASS"
    except (ValueError, OSError, KeyError, TypeError) as exc:
        result["reason"] = str(exc)
    write(output, result)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(f"\n**Day39 offline decision:** `{result['decision']}`\n\n")
        summary.write("AWS deployment authorization: **false**\n")
    return 0 if result["decision"] == "OFFLINE_VERIFICATION_PASS" else 1


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
