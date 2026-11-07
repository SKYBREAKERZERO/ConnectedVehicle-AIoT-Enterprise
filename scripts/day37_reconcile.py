"""Day37 independent live AWS + Terraform zero-drift reconciliation proof.

Reads actual Day37 GitHub/S3 evidence; calls existing day37_aws live verifiers.
No `--verified` flag or unsigned Boolean can bypass the live AWS call.
"""
from __future__ import annotations

import argparse
import os
import sys
import subprocess
from typing import Any

from scripts.day37_fence import Blocked, current_identity, env, load, require, write, same


def zero_drift(plan: dict[str, Any]) -> None:
    require(isinstance(plan.get("format_version"), str), "Terraform plan format absent")
    require(plan.get("errored") is not True, "Terraform plan errored")
    # `-detailed-exitcode` must separately have returned 0. Never infer it from
    # the JSON because provider refresh or failures might not be represented.
    require(not plan.get("resource_drift"), "Terraform detected resource drift")
    changes = plan.get("resource_changes", [])
    require(isinstance(changes, list), "resource_changes invalid")
    for item in changes:
        require(type(item) is dict, "resource change malformed")
        action = item.get("change", {}).get("actions")
        require(action == ["no-op"], f"resource drift or unknown action: {item.get('address')}")
    outputs = plan.get("output_changes", {})
    require(type(outputs) is dict, "output changes malformed")
    for name, item in outputs.items():
        require(type(item) is dict and item.get("actions") == ["no-op"], "output drift: " + str(name))


def validate_origin(fence: dict[str, Any]) -> None:
    ident = current_identity()
    require(fence.get("schema") == 2 and fence.get("state") == "ACTIVE", "untrusted active fence")
    for key in ident:
        require(fence.get(key) == ident[key], "fence origin mismatch: " + key)


def live_aws(phase: str, identity: dict[str, Any], release: dict[str, Any] | None) -> dict[str, Any]:
    # Existing project helper validates STS identity, exact ECR repo encryption,
    # ECS running task digest/ENI, and ALB targets. It makes real AWS CLI calls.
    from scripts.day37_aws import bootstrap_verify, check_ecr, service_readback
    account = env("DAY37_ACCOUNT_ID")
    repo = env("DAY37_ECR_REPOSITORY")
    cluster = env("DAY37_CLUSTER")
    if phase == "bootstrap":
        dest = os.environ.get("DAY37_BOOTSTRAP_LIVE_PROOF_PATH", ".day37/bootstrap/live-recheck.json")
        from pathlib import Path
        record = bootstrap_verify(account, repo, cluster, Path(dest))
        require(record.get("decision") == "STAGING_INFRA_BOOTSTRAPPED", "bootstrap live proof incorrect")
        require(record.get("aws_account_id") == account, "bootstrap account mismatch")
        return record
    require(release is not None, "deploy release required")
    require(release.get("commit") == identity["commit"] and release.get("signature_verified") is True,
            "untrusted release provenance")
    require(release.get("registry_digest") == identity.get("image_digest"), "image digest differs from Plan")
    uri = release.get("image_uri", "")
    require(isinstance(uri, str) and uri.endswith("@" + identity["image_digest"]), "image URI mismatch")
    check_ecr(repo, account)
    result = service_readback(account, cluster, env("DAY37_SERVICE"), env("DAY37_ALB_TARGET_GROUP_ARN"), uri, 2)
    require(result.get("decision") == "ECS_TASK_DIGEST_HEALTH_VERIFIED", "ECS/ALB check refused")
    require(result.get("registry_digest") == identity["image_digest"], "runtime digest mismatch")
    return result


def proof(identity: dict[str, Any], terraform: dict[str, Any], observed: dict[str, Any],
          *, terraform_exit_code: int) -> dict[str, Any]:
    validate_origin(identity)
    require(terraform_exit_code == 0, "Terraform detailed exit code not zero")
    zero_drift(terraform)
    phase = identity.get("phase")
    require(phase in ("bootstrap", "deploy"), "invalid phase")
    require(observed.get("aws_account_id") == identity["aws_account_id"], "AWS verifier wrong account")
    for key in ("commit", "run_id", "run_attempt"):
        require(str(observed.get(key)) == identity[key], "AWS verification from different run")
    expect = "STAGING_INFRA_BOOTSTRAPPED" if phase == "bootstrap" else "ECS_TASK_DIGEST_HEALTH_VERIFIED"
    require(observed.get("decision") == expect, "unexpected AWS decision")
    require(observed.get("production_authorized") is False and observed.get("release_authorized") is False,
            "AWS verification not limited to Staging")
    return {**identity, "decision": "AWS_AND_TERRAFORM_RECONCILED", "terraform_exit_code": 0,
            "live_aws_verified": True, "aws_decision": expect,
            "production_authorized": False, "release_authorized": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=("bootstrap", "deploy"), required=True)
    ap.add_argument("--fence", required=True)
    ap.add_argument("--terraform-json", required=True)
    ap.add_argument("--terraform-exit-code", type=int, required=True)
    ap.add_argument("--release")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    try:
        identity = load(args.fence)
        require(identity.get("phase") == args.phase, "phase mismatch")
        if args.phase == "deploy":
            require(bool(args.release), "signed release evidence required")
            # Validate signature and registry digest again, not a JSON Boolean.
            subprocess.run(["bash", "scripts/day37_tf.sh", "verify-release", args.release],
                           check=True, capture_output=True, timeout=120)
        result = live_aws(args.phase, identity, load(args.release) if args.release else None)
        decision = proof(identity, load(args.terraform_json), result, terraform_exit_code=args.terraform_exit_code)
        write(args.output, decision)
        return 0
    except (Blocked, KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
