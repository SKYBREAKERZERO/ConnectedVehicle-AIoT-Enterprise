"""Day37 approval/evidence adaptation for actual Day37 producer schemas.

Complements scripts.day37_gate (source of truth for final evidence), never
manufactures READY from a `--verified` switch or a manual checkmark.
"""
from __future__ import annotations

import argparse
import json
import os
import hashlib
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from scripts.day37_fence import (Blocked, canonical, current_identity, digest_file, env,
                                 identity_from_receipt, load, require, same, s3, write)

EXPECTED_DECISIONS = {"audit": "READY_FOR_CONFIGURATION_REVIEW",
                      "plan": "READY_FOR_STAGING_PLAN_REVIEW",
                      "bootstrap": "AWS_STAGING_INFRA_BOOTSTRAPPED",
                      "deploy": "AWS_STAGING_SERVICE_VERIFIED"}
JOB_SETS = {"audit": {"source"}, "plan": {"source", "admission", "plan"},
            "bootstrap": {"source", "admission", "plan", "bootstrap", "bootstrap_close"},
            "deploy": {"source", "admission", "publish", "deploy_plan", "deploy", "verify", "close"}}
ALL_JOBS = {"source", "admission", "publish", "plan", "bootstrap", "deploy_plan",
            "deploy", "verify", "close", "recovery", "bootstrap_close"}


def binding(phase: str, receipt_path: str, summary: str, sha: str,
            release_path: str | None, checkpoint: str | None) -> None:
    receipt = load(receipt_path)
    require(receipt.get("plan_sha256") == sha, "reviewed Plan SHA mismatched")
    _ = identity_from_receipt(receipt, phase, summary,
                              load(release_path) if release_path else None, checkpoint)
    print("EXACT_PLAN_BINDING_OK", phase, sha)


def closure(receipt_path: str, proof_path: str, sha: str, release_path: str) -> None:
    fence = load(receipt_path)
    proof = load(proof_path)
    release = load(release_path)
    require(fence.get("phase") == "deploy" and fence.get("plan_sha256") == sha,
            "fence approved SHA mismatch")
    require(same(fence, proof) and proof.get("decision") == "AWS_AND_TERRAFORM_RECONCILED",
            "fence/proof binding mismatch")
    require(proof.get("live_aws_verified") is True and proof.get("terraform_exit_code") == 0,
            "cannot close without live AWS and no-op Terraform")
    require(release.get("registry_digest") == fence.get("image_digest") and
            release.get("signature_verified") is True, "release digest/signature mismatch")
    current = current_identity()
    for k, v in current.items():
        require(fence.get(k) == v, "fence from different run")


def checkpoint_status(repo: str, run_id: str, attempt: str, output: str) -> None:
    require(repo == env("GITHUB_REPOSITORY") and run_id == env("GITHUB_RUN_ID") and
            attempt == env("GITHUB_RUN_ATTEMPT"), "wrong checkpoint lookup origin")
    token = env("GH_TOKEN")
    name = f"day37-checkpoint-{run_id}-{attempt}"
    found: list[dict] = []
    for page in range(1, 21):
        url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
        req = Request(url, headers={"Authorization": "Bearer " + token,
                                    "Accept": "application/vnd.github+json",
                                    "X-GitHub-Api-Version": "2022-11-28"})
        with urlopen(req, timeout=15) as r:
            result = json.load(r)
        entries = result.get("artifacts")
        require(isinstance(entries, list), "GitHub Artifact enumeration failed")
        found.extend(e for e in entries if e.get("name") == name and e.get("expired") is False)
        if len(entries) < 100:
            break
    else:
        raise Blocked("ambiguous artifact enumeration")
    require(len(found) < 2, "ambiguous checkpoint artifacts")
    write(output, {"checkpoint_exists": str(bool(found)).lower(), "decision": "OBSERVED" if found else "CHECKPOINT_MISSING_BLOCKED"})


def recovery_admission(checkpoint: str, fence_artifact: str) -> None:
    # Must read the live ACTIVE S3 fence; GitHub Artifact alone is never authority.
    s3().recovery_check(checkpoint, load(fence_artifact))


def final_check(mode: str, folder: str, result_path: str) -> None:
    require(mode in EXPECTED_DECISIONS, "invalid mode")
    raw = json.loads(env("PIPELINE_NEEDS"))
    require(isinstance(raw, dict) and set(raw) == ALL_JOBS, "unexpected CI DAG")
    expected_jobs = JOB_SETS[mode]
    for job in ALL_JOBS:
        expected = "success" if job in expected_jobs else "skipped"
        require(isinstance(raw.get(job), dict) and raw[job].get("result") == expected,
                "incorrect job state " + job)
    result = load(result_path)
    require(result.get("decision") == EXPECTED_DECISIONS[mode], "final gate decision mismatch")
    require(result.get("production_authorized") is False and result.get("release_authorized") is False,
            "production authority must be denied")
    require(result.get("commit") == env("GITHUB_SHA") and
            str(result.get("run_id")) == env("GITHUB_RUN_ID") and
            str(result.get("run_attempt")) == env("GITHUB_RUN_ATTEMPT"), "foreign final receipt")
    files = {"audit": [], "plan": ["admission/admission.json", "plan/plan-summary.json"],
             "bootstrap": ["admission/admission.json", "plan/receipt.json", "bootstrap/bootstrap.json"],
             "deploy": ["admission/admission.json", "publish/release.json", "deploy-plan/receipt.json",
                        "deploy/deployment.json", "verify/verified.json", "close/closed.json"]}[mode]
    for relative in files:
        digest_file(Path(folder) / relative)
    if mode in ("bootstrap", "deploy"):
        phase_root = "bootstrap" if mode == "bootstrap" else "close"
        receipt_name = "bootstrap/closed-fence.json" if mode == "bootstrap" else "close/fence-closed.json"
        receipt = load(Path(folder) / receipt_name)
        reconciliation = load(Path(folder) / phase_root / "proof.json")
        source_receipt = load(Path(folder) / ("plan/receipt.json" if mode == "bootstrap" else "deploy-plan/receipt.json"))
        require(receipt.get("schema") == 2 and receipt.get("state") == "CLOSED", "S3 closure receipt absent")
        require(receipt.get("phase") == mode and
                receipt.get("plan_sha256") == source_receipt.get("plan_sha256") and
                receipt.get("policy_sha256") == source_receipt.get("policy_sha256"),
                "S3 closure Plan/Policy differs from stored Plan")
        require(receipt.get("proof_sha256") == hashlib.sha256(canonical(reconciliation)).hexdigest(),
                "S3 fence close proof hash mismatch")
        require(same(receipt, reconciliation) and
                reconciliation.get("decision") == "AWS_AND_TERRAFORM_RECONCILED" and
                reconciliation.get("terraform_exit_code") == 0 and
                reconciliation.get("live_aws_verified") is True,
                "missing bound AWS/zero-drift close proof")
        for k in ("commit", "run_id", "run_attempt"):
            require(str(receipt.get(k)) == env("GITHUB_"+{"commit":"SHA","run_id":"RUN_ID","run_attempt":"RUN_ATTEMPT"}[k]),
                    "foreign S3 close receipt")


def main() -> int:
    p = argparse.ArgumentParser()
    commands = p.add_subparsers(dest="cmd", required=True)
    b = commands.add_parser("binding")
    b.add_argument("--phase", choices=("bootstrap", "deploy"), required=True)
    b.add_argument("--receipt", required=True)
    b.add_argument("--summary", required=True)
    b.add_argument("--sha256", required=True)
    b.add_argument("--release")
    b.add_argument("--checkpoint")
    c = commands.add_parser("closure")
    c.add_argument("--receipt", required=True)
    c.add_argument("--proof", required=True)
    c.add_argument("--sha256", required=True)
    c.add_argument("--release", required=True)
    cp = commands.add_parser("checkpoint")
    for arg in ("repo", "run-id", "attempt", "output"):
        cp.add_argument("--" + arg, required=True)
    skip = commands.add_parser("skipped-recovery")
    skip.add_argument("--output", required=True)
    rec = commands.add_parser("recovery-admission")
    rec.add_argument("--checkpoint", required=True)
    rec.add_argument("--fence", required=True)
    f = commands.add_parser("final-check")
    f.add_argument("--mode", choices=tuple(EXPECTED_DECISIONS), required=True)
    f.add_argument("--folder", required=True)
    f.add_argument("--final", required=True)
    a = p.parse_args()
    try:
        if a.cmd == "binding":
            binding(a.phase, a.receipt, a.summary, a.sha256, a.release, a.checkpoint)
        elif a.cmd == "closure":
            closure(a.receipt, a.proof, a.sha256, a.release)
        elif a.cmd == "checkpoint":
            checkpoint_status(a.repo, a.run_id, a.attempt, a.output)
        elif a.cmd == "skipped-recovery":
            write(a.output, {"decision": "BLOCKED_NO_CHECKPOINT", "rollback_attempted": False,
                             "manual_reconciliation_required": True, "production_authorized": False})
        elif a.cmd == "recovery-admission":
            recovery_admission(a.checkpoint, a.fence)
        elif a.cmd == "final-check":
            final_check(a.mode, a.folder, a.final)
        return 0
    except (Blocked, TypeError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        # The upstream day37_gate may have written a nominal success before
        # this independent guard ran. Never publish a misleading READY artifact.
        if a.cmd == "final-check":
            write(a.final, {"decision": "BLOCKED", "mode": a.mode,
                            "reason": "INDEPENDENT_DAY37_P0_GUARD_REJECTED",
                            "commit": os.environ.get("GITHUB_SHA", ""),
                            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                            "production_authorized": False, "release_authorized": False})
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
