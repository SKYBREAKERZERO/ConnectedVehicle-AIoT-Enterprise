"""Separate, recovery-role-only reconciliation for a failed Bootstrap Apply.

No Terraform Apply or automatic infrastructure destruction occurs here.
The already-corrected infrastructure must be proven No-Op before closure.
"""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path
from scripts.day37_fence import Blocked, current_identity, env, load, require, s3, write
from scripts.day37_reconcile import zero_drift


def bootstrap_manual_proof(fence: dict, terraform: dict, observed: dict, exit_code: int) -> dict:
    now = current_identity()
    require(fence.get("schema") == 2 and fence.get("state") == "ACTIVE" and
            fence.get("phase") == "bootstrap", "expected ACTIVE bootstrap fence")
    require(fence.get("aws_account_id") == now["aws_account_id"] and
            fence.get("repository") == now["repository"], "foreign staging identity")
    for tag, key in (("COMMIT", "commit"), ("RUN", "run_id"), ("ATTEMPT", "run_attempt")):
        require(fence.get(key) == env("RECONCILE_PRIOR_" + tag), "prior run differs from active fence")
    require(exit_code == 0, "Terraform detailed exit code not zero")
    zero_drift(terraform)
    variables = terraform.get("variables", {})
    require(variables.get("enable_service", {}).get("value") is False and
            variables.get("desired_count", {}).get("value") == 0,
            "bootstrap reconciliation must keep service disabled")
    require(observed.get("decision") == "STAGING_INFRA_BOOTSTRAPPED" and
            observed.get("aws_account_id") == now["aws_account_id"] and
            observed.get("production_authorized") is False and
            observed.get("release_authorized") is False,
            "independent bootstrap AWS verification absent")
    for key in ("commit", "run_id", "run_attempt"):
        require(str(observed.get(key)) == now[key], "AWS verification from another reconciliation run")
    return {
        "decision": "MANUAL_BOOTSTRAP_AWS_AND_TERRAFORM_RECONCILED",
        "phase": "bootstrap",
        "prior_commit": fence["commit"],
        "prior_run_id": fence["run_id"],
        "prior_run_attempt": fence["run_attempt"],
        "prior_plan_sha256": fence["plan_sha256"],
        "prior_policy_sha256": fence["policy_sha256"],
        "reconciler_commit": now["commit"],
        "reconciler_run_id": now["run_id"],
        "reconciler_run_attempt": now["run_attempt"],
        "repository": now["repository"],
        "aws_account_id": now["aws_account_id"],
        "restored_registry_digest": None,
        "terraform_exit_code": 0,
        "live_aws_verified": True,
        "production_authorized": False,
        "release_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--fence", required=True)
    p.add_argument("--terraform-json", required=True)
    p.add_argument("--terraform-exit-code", required=True, type=int)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    try:
        record = load(a.fence)
        live, _ = s3().read()
        require(live == record, "S3 ACTIVE fence differs from provided identity")
        from scripts.day37_aws import bootstrap_verify
        observed = bootstrap_verify(env("DAY37_ACCOUNT_ID"), env("DAY37_ECR_REPOSITORY"),
                                    env("DAY37_CLUSTER"), Path(".day37/bootstrap-manual/live-aws.json"))
        result = bootstrap_manual_proof(record, load(a.terraform_json), observed, a.terraform_exit_code)
        write(a.output, result)
        return 0
    except (Blocked, KeyError, TypeError, ValueError, OSError) as error:
        print("BLOCKED: bootstrap reconciliation: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
