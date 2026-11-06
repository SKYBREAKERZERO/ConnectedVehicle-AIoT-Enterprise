"""Day32 module/deployment acceptance, explicitly separate from trusted promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from scripts.iac.day31_evidence import provenance
from scripts.iac.deployment_probe import CHECKS
from scripts.iac.module_contracts import GROUPS, merge_reports


def evidence(folder: Path) -> dict[str, Any]:
    names = [
        "summary.json",
        "contracts.json",
        "security.json",
        "day32-deployment.json",
        "day31-governance.json",
    ]
    documents = {name: json.loads((folder / name).read_text(encoding="utf-8")) for name in names}
    deployment = documents["day32-deployment.json"]
    if (
        type(deployment.get("version")) is not int
        or deployment.get("version") != 1
        or deployment.get("scope") != "localstack_only"
        or deployment.get("provenance") != provenance()
        or not isinstance(deployment.get("checks"), dict)
        or set(deployment["checks"]) != CHECKS
        or any(value is not True for value in deployment["checks"].values())
        or deployment.get("real_aws_verified") is not False
        or deployment.get("production_apply_enabled") is not False
        or deployment.get("deployed_roots") != ["environments/local", "environments/ota-local"]
        or not re.fullmatch("[0-9a-f]{64}", deployment.get("terraform_outputs_sha256", ""))
    ):
        raise ValueError("Day32 deployment identity/scope/checks invalid")
    counts = deployment.get("observed_counts", {})
    if set(counts) != {"sqs_messages", "kms_keys", "secrets", "iam_roles"} or any(
        type(n) is not int or n <= 0 for n in counts.values()
    ):
        raise ValueError("Day32 observed deployment counters required")
    contracts = documents["contracts.json"]
    if merge_reports(contracts["contract_groups"]) != contracts:
        raise ValueError("Day32 module aggregate mismatch")
    summary = documents["summary.json"]
    if (
        summary.get("status") != "passed"
        or summary.get("phase") != "assembled-dag"
        or summary.get("contract_runs") != contracts["contract_runs"]
        or summary.get("module_contract_groups") != list(GROUPS)
        or summary.get("destroy_actions") != 0
        or summary.get("second_plan_exit_code") != 0
        or summary.get("ota_local_apply_second_plan") is not True
        or summary.get("security_scan") != "passed"
        or documents["security.json"]
        != {
            "status": "passed",
            "phase": "security",
            "security_scan": "passed",
            "scanned_sources": 2,
        }
    ):
        raise ValueError("Day32 deployment/plan/security gate incomplete")
    prior = documents["day31-governance.json"]
    if (
        prior.get("provenance") != provenance()
        or prior.get("apply_authorized") is not False
        or prior.get("cross_workflow_binding_completed") is not False
    ):
        raise ValueError("Day32 prior governance identity mismatch")
    # Bind the selected exact bytes, including the live receipt, not hand-written PASS flags.
    return {
        "version": 1,
        "status": "passed",
        "scope": "localstack_iac_acceptance",
        "provenance": provenance(),
        "module_groups": list(GROUPS),
        "terraform_contracts": contracts["contract_runs"],
        "deployment_checks": sorted(CHECKS),
        "observed_counts": counts,
        "proof_sha256": {
            name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in names
        },
        "trusted_main_promotion_verified": False,
        "independent_approval_verified": False,
        "release_authorized": False,
        "production_apply_enabled": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(".iac-reports"))
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    expected = evidence(args.directory)
    path = args.directory / "day32-acceptance.json"
    if args.verify:
        if json.loads(path.read_text(encoding="utf-8")) != expected:
            raise ValueError("Day32 acceptance changed or replayed")
    else:
        path.write_text(json.dumps(expected, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Day32 LocalStack module/deployment acceptance PASS; no production authority")


if __name__ == "__main__":
    main()
