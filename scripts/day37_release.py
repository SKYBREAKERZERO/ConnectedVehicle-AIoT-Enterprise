"""Day37 contract/readiness inspection only. No AWS credentials, push or deploy executor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from scripts.day35_workflow_gate import load
from scripts.day36_staging import ROOT, command
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.plan_admission import ruleset_errors
from scripts.iac.workflow_evidence_binding import GitHub

REPOSITORY = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
PHASES = ("admission", "artifact", "identity", "plan", "deploy", "rollback")
CASES = {
    "admission": ["pr", "branch", "sha", "self-review", "unapproved", "attempt"],
    "artifact": ["tag", "local-id", "digest", "unsigned", "missing-sbom"],
    "identity": ["account", "region", "subject", "audience", "production-role"],
    "plan": ["destroy", "secret", "state", "missing-plan"],
    "deploy": ["enabled", "credentials"],
    "rollback": ["failed", "schema", "uncompleted-old", "duplicate-command", "ecu-floor"],
}
FILES = [
    "infra/terraform/modules/ota-staging/.terraform.lock.hcl",
    "infra/terraform/environments/ota-staging/main.tf.example",
    "infra/terraform/environments/ota-staging/variables.tf.example",
    "infra/terraform/environments/ota-staging/versions.tf.example",
    "scripts/day37_release.py",
    "tests/unit/test_day37_release.py",
    ".github/workflows/day37-staging.yml",
    "infra/terraform/modules/ota-staging/main.tf",
    "infra/terraform/modules/ota-staging/variables.tf",
    "infra/terraform/modules/ota-staging/versions.tf",
    "infra/terraform/modules/ota-staging/tests/contracts.tftest.hcl",
]


def provenance() -> dict[str, str]:
    digest = hashlib.sha256()
    for name in sorted(FILES):
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes())
    return {
        "day37_commit": os.environ.get("GITHUB_SHA") or command(["git", "rev-parse", "HEAD"]),
        "day37_run_id": os.environ.get("GITHUB_RUN_ID", "local")
        + ":"
        + os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "day37_source_sha256": digest.hexdigest(),
    }


def contract_errors(phase: str, data: dict[str, Any]) -> list[str]:
    """Pure negative-test policy, NOT authenticated GitHub/AWS/Cosign evidence."""
    errors: list[str] = []
    if phase == "admission":
        if data["event"] != "workflow_dispatch" or data["ref"] != "refs/heads/main":
            errors.append("protected_main_dispatch_required")
        if data["commit"] != data["approved_commit"] or not re.fullmatch(
            "[0-9a-f]{40}", data["commit"]
        ):
            errors.append("candidate_changed_after_review")
        if data["approved"] is not True or data["reviewer"] == data["requester"]:
            errors.append("independent_approval_required")
        if type(data["attempt"]) is not int or data["attempt"] != data["evidence_attempt"]:
            errors.append("attempt_replay")
    elif phase == "artifact":
        digest = data["registry_manifest_digest"]
        if not re.fullmatch("sha256:[0-9a-f]{64}", digest):
            errors.append("registry_manifest_digest_required")
        if data["identity_kind"] != "registry-manifest" or data["ecr_observed_digest"] != digest:
            errors.append("local_id_or_ecr_manifest_mismatch")
        if data["signature_valid"] is not True or data["sbom_bound"] is not True:
            errors.append("verified_signature_and_sbom_required")
    elif phase == "identity":
        if data["account"] != data["expected_account"] or data["region"] != "ap-northeast-1":
            errors.append("wrong_aws_target")
        if (
            data["sub"] != f"repo:{REPOSITORY}:environment:aws-staging"
            or data["aud"] != "sts.amazonaws.com"
        ):
            errors.append("oidc_trust_mismatch")
        if (
            data["role_arn"]
            != f"arn:aws:iam::{data['expected_account']}:role/connected-vehicle-ota-staging-github"
        ):
            errors.append("staging_role_mismatch")
    elif phase == "plan":
        if data["plan_bound"] is not True or data["destroy_count"] != 0:
            errors.append("reviewed_non_destructive_plan_required")
        if data["contains_secret_value"] is not False or data["contains_state"] is not False:
            errors.append("sensitive_evidence_forbidden")
    elif phase == "deploy":
        if data["live_execution_enabled"] is not False or data["uses_aws_credentials"] is not False:
            errors.append("day37_live_execution_disabled")
    elif phase == "rollback":
        if data["rollback_state"] != "COMPLETED" or data["previous_state"] != "COMPLETED":
            errors.append("verified_completed_rollback_required")
        if data["schema_before"] != data["schema_after"]:
            errors.append("schema_incompatible_manual_recovery_required")
        if data["command_count"] != 1 or data["outbox_count"] != 1:
            errors.append("duplicate_business_side_effect")
        if data["ecu_security_after"] < data["ecu_security_before"]:
            errors.append("ecs_rollback_cannot_reset_ecu_security_floor")
    else:
        raise ValueError("Unknown contract phase")
    return errors


def redact_guard(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(
                r"password|secret_value|access_key|session_token|tfstate|raw_plan|raw_log",
                key,
                re.I,
            ):
                raise ValueError("Sensitive/raw deployment evidence forbidden")
            redact_guard(item)
    elif isinstance(value, str) and re.search(
        r"AKIA[A-Z0-9]{16}|BEGIN.*PRIVATE KEY|password\s*=", value, re.I
    ):
        raise ValueError("Credential-like evidence value forbidden")
    elif isinstance(value, list):
        for item in value:
            redact_guard(item)


def inspect_readiness(api: GitHub, pr: int) -> dict[str, Any]:
    """Observe real GitHub facts; unavailable or incomplete facts stay blocked."""
    candidate = command(["git", "rev-parse", "HEAD"])
    main = api.get("git/ref/heads/main")["object"]["sha"]
    pull = api.get(f"pulls/{pr}")
    rules = api.get("rulesets/24828733")
    blockers = []
    if candidate != main:
        blockers.append("candidate_not_protected_main")
    if pull["merged_at"] is None:
        blockers.append("protected_merge_not_completed")
    if ruleset_errors(rules):
        blockers.append("complete_main_governance_not_verified")
    reviews = api.get(f"pulls/{pr}/reviews?per_page=100")
    independent = [
        r
        for r in reviews
        if r["state"] == "APPROVED"
        and r["commit_id"] == pull["head"]["sha"]
        and r["user"]["login"] != pull["user"]["login"]
    ]
    # Approval count is observational only; no collaborator/merge-time authority
    # is inferred here. Protected-main admission remains an unmet prerequisite.
    if not independent:
        blockers.append("independent_review_missing")
    blockers.extend(
        [
            "day36_same_candidate_supply_chain_not_admitted",
            "registry_manifest_signature_and_provenance_not_verified",
            "aws_state_backed_plan_not_verified",
            "aws_staging_execution_not_enabled",
        ]
    )
    return {
        "provenance": provenance(),
        "decision": "BLOCKED",
        "blockers": blockers,
        "observed_main_sha": main,
        "observed_pr_head": pull["head"]["sha"],
        "observed_approval_count": len(independent),
        "production_authorized": False,
        "aws_deployment_verified": False,
        "signature_verified": False,
    }


TF_RUNS = (
    "staging_release_boundaries",
    "deny_mutable_tag",
    "deny_foreign_account_secret",
    "deny_other_region",
    "deny_public_ingress",
    "deny_secret_other_region",
)


def terraform_summary(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 10_000_000:
        raise ValueError("Bounded Terraform test stream required")
    events = [json.loads(line) for line in raw.splitlines()]
    summaries = [e["test_summary"] for e in events if e.get("type") == "test_summary"]
    runs = {
        e["test_run"]["run"]: e["test_run"]["status"]
        for e in events
        if e.get("type") == "test_run" and e["test_run"].get("progress") == "complete"
    }
    if len(summaries) != 1 or set(runs) != set(TF_RUNS) or any(v != "pass" for v in runs.values()):
        raise ValueError("All six mock-provider plan contracts must execute and pass")
    return {
        "provenance": provenance(),
        "summary": summaries[0],
        "runs": runs,
        "execution_log_sha256": hashlib.sha256(raw).hexdigest(),
        "execution": "mock-provider-plan-only",
        "real_aws_plan_verified": False,
    }


def receipt(phase: str, junit: Path, terraform_report: Path | None = None) -> dict[str, Any]:
    required = {f"test_{phase}_denies_invalid_request[{case}]" for case in CASES[phase]}
    raw = junit.read_bytes()
    xml_cases(raw, required, provenance(), exact=True)
    result: dict[str, Any] = {
        "phase": phase,
        "provenance": provenance(),
        "contract_tests_verified": True,
        "junit_sha256": hashlib.sha256(raw).hexdigest(),
        "production_authorized": False,
        "aws_deployment_verified": False,
    }
    if phase == "plan":
        if terraform_report is None:
            raise ValueError("Actual mock-provider Terraform report required")
        summary = load(terraform_report)
        if (
            summary["provenance"] != provenance()
            or summary["summary"]
            != {"status": "pass", "passed": 6, "failed": 0, "errored": 0, "skipped": 0}
            or set(summary["runs"]) != set(TF_RUNS)
            or any(value != "pass" for value in summary["runs"].values())
            or summary["real_aws_plan_verified"] is not False
        ):
            raise ValueError("Incomplete Terraform mock plan contracts")
        result["terraform_mock_plan_verified"] = True
        result["terraform_report_sha256"] = hashlib.sha256(
            terraform_report.read_bytes()
        ).hexdigest()
        result["aws_plan_verified"] = False
    return result


def gate(folder: Path, needs: dict[str, Any]) -> dict[str, Any]:
    if set(needs) != set(PHASES) or any(v["result"] != "success" for v in needs.values()):
        raise ValueError("All six contract/readiness nodes must finish successfully")
    proofs = {}
    for phase in PHASES:
        observed = load(folder / (phase + ".json"))
        if observed != receipt(
            phase,
            folder / (phase + ".xml"),
            folder / "terraform-summary.json" if phase == "plan" else None,
        ):
            raise ValueError("Independent contract receipt recomputation failed")
        redact_guard(observed)
        proofs[phase] = hashlib.sha256((folder / (phase + ".json")).read_bytes()).hexdigest()
    readiness = load(folder / "readiness.json")
    if readiness["provenance"] != provenance() or readiness["decision"] != "BLOCKED":
        raise ValueError("Unqualified or mismatched live-readiness observation")
    redact_guard(readiness)
    proofs["readiness"] = hashlib.sha256((folder / "readiness.json").read_bytes()).hexdigest()
    return {
        "decision": "BLOCKED",
        "offline_contracts_verified": True,
        "provenance": provenance(),
        "blockers": readiness["blockers"],
        "proofs": proofs,
        "aws_deployment_verified": False,
        "sts_identity_verified": False,
        "registry_publication_verified": False,
        "signature_verified": False,
        "production_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "receipt", "terraform-summary", "gate"))
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--pr", type=int, default=15)
    parser.add_argument("--folder", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--terraform-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect_readiness(GitHub(), args.pr)
        elif args.command == "terraform-summary":
            if args.input is None:
                raise ValueError("Terraform JSON event stream required")
            result = terraform_summary(args.input)
        elif args.command == "receipt":
            if args.phase is None or args.junit is None:
                raise ValueError("Phase and actual JUnit required")
            result = receipt(args.phase, args.junit, args.terraform_report)
        else:
            if args.folder is None:
                raise ValueError("Independent evidence directory required")
            result = gate(args.folder, json.loads(os.environ.get("PIPELINE_NEEDS", "{}")))
    except (ValueError, OSError, KeyError, TypeError) as error:
        result = {
            "decision": "BLOCKED",
            "offline_contracts_verified": False,
            "reason": str(error),
            "provenance": provenance(),
            "production_authorized": False,
            "aws_deployment_verified": False,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    if (args.command == "gate" or result.get("offline_contracts_verified") is False) and result.get(
        "decision"
    ) == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
