"""Bound, private S3 Terraform plan handoff and durable staging deployment fence.

The plan bytes are NEVER a GitHub artifact. They remain in a versioned, SSE-KMS S3
bucket, with immutable per-run object names. All operations reject foreign accounts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day37_gate import PRODUCTION_FALSE, SHA, dump, strict_load

REGION = "ap-northeast-1"
PHASES = {"bootstrap", "deploy"}
HEX = re.compile(r"[a-f0-9]{64}\Z")
KEY = re.compile(r"[a-z0-9/_-]{12,220}\Z")


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value == "null":
        raise ValueError("BLOCKED: required Plan transport setting absent: " + name)
    return value


def identity() -> dict[str, str]:
    result = {
        "commit": env("GITHUB_SHA"),
        "run_id": env("GITHUB_RUN_ID"),
        "run_attempt": env("GITHUB_RUN_ATTEMPT"),
    }
    if (
        not SHA.fullmatch(result["commit"])
        or not result["run_id"].isdigit()
        or not result["run_attempt"].isdigit()
    ):
        raise ValueError("BLOCKED: invalid source/Run/Attempt identity")
    if (
        os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
    ):
        raise ValueError("BLOCKED: plan transport restricted to dispatched protected main")
    return result


def config() -> dict[str, str]:
    account = env("DAY37_ACCOUNT_ID")
    bucket = env("DAY37_PLAN_BUCKET")
    kms = env("DAY37_PLAN_KMS_ARN")
    prefix = env("DAY37_PLAN_PREFIX").strip("/")
    if not re.fullmatch(r"[0-9]{12}", account) or account == "0" * 12:
        raise ValueError("BLOCKED: foreign/placeholder account")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{3,62}", bucket) or "staging" not in bucket:
        raise ValueError("BLOCKED: plan bucket must be staging-scoped")
    if kms != env("DAY37_BACKEND_KMS_ARN") or not kms.startswith(
        f"arn:aws:kms:{REGION}:{account}:key/"
    ):
        raise ValueError("BLOCKED: plan bucket KMS key must be same-account reviewed backend key")
    if (
        not KEY.fullmatch(prefix)
        or not prefix.startswith("connected-vehicle/day37-plans/")
        or ".." in prefix
    ):
        raise ValueError("BLOCKED: unsafe plan prefix")
    return {"account": account, "bucket": bucket, "kms": kms, "prefix": prefix}


def command(args: list[str], *, timeout: int = 50) -> dict[str, Any]:
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        # AWS errors and Terraform plans could contain credentials. Do not echo stderr.
        raise ValueError("BLOCKED: S3 plan/fence operation failed: " + " ".join(args[1:3]))
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("BLOCKED: malformed AWS JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("BLOCKED: AWS response not an object")
    return data


def s3(*args: str) -> dict[str, Any]:
    return command(["aws", "s3api", *args, "--region", REGION, "--output", "json"])


def check_bucket(c: dict[str, str]) -> None:
    s3("head-bucket", "--bucket", c["bucket"], "--expected-bucket-owner", c["account"])
    version = s3(
        "get-bucket-versioning", "--bucket", c["bucket"], "--expected-bucket-owner", c["account"]
    )
    if version.get("Status") != "Enabled":
        raise ValueError("BLOCKED: Plan bucket versioning disabled")


def key(phase: str, c: dict[str, str], i: dict[str, str]) -> str:
    if phase not in PHASES:
        raise ValueError("BLOCKED: invalid saved Plan phase")
    return f"{c['prefix']}/{i['run_id']}/{i['run_attempt']}/{i['commit']}/{phase}.tfplan"


def store(phase: str, plan: Path, summary: Path, output: Path) -> dict[str, Any]:
    i, c = identity(), config()
    check_bucket(c)
    if plan.is_symlink() or not plan.is_file() or not 0 < plan.stat().st_size <= 100 * 1024 * 1024:
        raise ValueError("BLOCKED: missing/unsafe binary Terraform Plan")
    summary_data = strict_load(summary)
    if summary_data.get("decision") != "NON_DESTRUCTIVE_TERRAFORM_PLAN":
        raise ValueError("BLOCKED: unapproved Terraform policy summary")
    digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    upload_key = key(phase, c, i)
    result = s3(
        "put-object",
        "--bucket",
        c["bucket"],
        "--key",
        upload_key,
        "--body",
        str(plan),
        "--if-none-match",
        "*",
        "--server-side-encryption",
        "aws:kms",
        "--ssekms-key-id",
        c["kms"],
        "--expected-bucket-owner",
        c["account"],
    )
    version = result.get("VersionId")
    if not isinstance(version, str) or not version or version == "null":
        raise ValueError("BLOCKED: missing S3 immutable object version")
    receipt: dict[str, Any] = {
        **i,
        "phase": phase,
        "aws_account_id": c["account"],
        "bucket": c["bucket"],
        "object_key": upload_key,
        "version_id": version,
        "kms_key_arn": c["kms"],
        "plan_sha256": digest,
        "plan_bytes": plan.stat().st_size,
        "policy_sha256": hashlib.sha256(summary.read_bytes()).hexdigest(),
        "image_digest": summary_data.get("image_digest"),
        "created_at": datetime.now(UTC).isoformat(),
        "decision": "PRIVATE_VERSIONED_PLAN_STORED",
        **PRODUCTION_FALSE,
    }
    dump(output, receipt)
    return receipt


def fetch(
    phase: str,
    receipt_path: Path,
    output: Path,
    expected_hash: str,
    policy_path: Path | None = None,
) -> None:
    i, c = identity(), config()
    check_bucket(c)
    receipt = strict_load(receipt_path)
    keys = {
        "aws_account_id": c["account"],
        "bucket": c["bucket"],
        "object_key": key(phase, c, i),
        "kms_key_arn": c["kms"],
        "phase": phase,
        "decision": "PRIVATE_VERSIONED_PLAN_STORED",
        **i,
    }
    if any(receipt.get(k) != v for k, v in keys.items()):
        raise ValueError("BLOCKED: plan receipt belongs to different source/attempt/account/phase")
    if not HEX.fullmatch(expected_hash) or receipt.get("plan_sha256") != expected_hash:
        raise ValueError("BLOCKED: reviewer-approved plan checksum differs")
    if policy_path is not None:
        if not policy_path.is_file() or hashlib.sha256(
            policy_path.read_bytes()
        ).hexdigest() != receipt.get("policy_sha256"):
            raise ValueError("BLOCKED: reviewed sanitized Plan policy differs from receipt")
        policy = strict_load(policy_path)
        if (
            policy.get("phase") != phase
            or policy.get("decision") != "NON_DESTRUCTIVE_TERRAFORM_PLAN"
            or policy.get("image_digest") != receipt.get("image_digest")
        ):
            raise ValueError("BLOCKED: Plan summary phase/digest mismatch")
    version = receipt.get("version_id", "")
    if not isinstance(version, str) or not version or len(version) > 200:
        raise ValueError("BLOCKED: invalid immutable S3 version ID")
    timestamp = datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
    seconds = (datetime.now(UTC) - timestamp).total_seconds()
    if not 0 <= seconds <= 4 * 3600:
        raise ValueError("BLOCKED: saved Plan expired/future-dated")
    if output.is_symlink():
        raise ValueError("BLOCKED: symlink destination")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    try:
        s3(
            "get-object",
            "--bucket",
            c["bucket"],
            "--key",
            keys["object_key"],
            "--version-id",
            version,
            "--expected-bucket-owner",
            c["account"],
            str(output),
        )
        if (
            not output.is_file()
            or output.stat().st_size != receipt["plan_bytes"]
            or hashlib.sha256(output.read_bytes()).hexdigest() != expected_hash
        ):
            raise ValueError("BLOCKED: private plan differs from exact approved bytes")
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def fence_key(c: dict[str, str]) -> str:
    return c["prefix"] + "/recovery/active.json"


def fence_clear() -> None:
    c = config()
    check_bucket(c)
    cmd = [
        "aws",
        "s3api",
        "head-object",
        "--bucket",
        c["bucket"],
        "--key",
        fence_key(c),
        "--expected-bucket-owner",
        c["account"],
        "--region",
        REGION,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if p.returncode == 0:
        raise ValueError("BLOCKED: unresolved ECS/Terraform reconciliation fence")
    # Do not mistake AccessDenied or AWS outage for absence.
    if not any(x in p.stderr for x in ("(404)", "Not Found", "NoSuchKey")):
        raise ValueError("BLOCKED: cannot prove absence of recovery fence")


def mark_fence(phase: str, receipt: Path, output: Path) -> None:
    if phase != "deploy":
        raise ValueError("BLOCKED: only deploy can require ECS reconciliation")
    i, c = identity(), config()
    record = strict_load(receipt)
    if any(record.get(k) != v for k, v in i.items()) or record.get("phase") != "deploy":
        raise ValueError("BLOCKED: invalid approved Plan binding for deployment fence")
    fence_clear()
    body = {
        **i,
        "phase": phase,
        "plan_sha256": record["plan_sha256"],
        "decision": "RECONCILIATION_REQUIRED",
        "aws_account_id": c["account"],
        **PRODUCTION_FALSE,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    dump(output, body)
    s3(
        "put-object",
        "--bucket",
        c["bucket"],
        "--key",
        fence_key(c),
        "--body",
        str(output),
        "--if-none-match",
        "*",
        "--server-side-encryption",
        "aws:kms",
        "--ssekms-key-id",
        c["kms"],
        "--expected-bucket-owner",
        c["account"],
    )


def close_fence(fence: Path, *, allow: bool, manual_prior: dict[str, str] | None = None) -> None:
    if not allow:
        raise ValueError("BLOCKED: fence clearing requires independent health + zero-drift proof")
    i, c = identity(), config()
    if (
        os.environ.get("DAY37_ROLE_ARN")
        != f"arn:aws:iam::{c['account']}:role/cv-ota-staging-recovery"
    ):
        raise ValueError("BLOCKED: only reviewed Recovery Role can close reconciliation fence")
    expected = strict_load(fence)
    proven_identity = manual_prior if manual_prior is not None else i
    if (
        expected.get("decision") != "RECONCILIATION_REQUIRED"
        or expected.get("aws_account_id") != c["account"]
        or expected.get("phase") != "deploy"
        or any(expected.get(k) != v for k, v in proven_identity.items())
    ):
        raise ValueError("BLOCKED: invalid fence closure receipt")
    # For manual reconciliation of a previous run the old run identity is permitted,
    # but never allow a different account/phase or mutable object key.
    actual = s3(
        "get-object",
        "--bucket",
        c["bucket"],
        "--key",
        fence_key(c),
        "--expected-bucket-owner",
        c["account"],
        str(fence.parent / ".fence-readback.json"),
    )
    live = strict_load(fence.parent / ".fence-readback.json")
    if live != expected:
        raise ValueError("BLOCKED: active fence does not match reviewed recovery receipt")
    version = actual.get("VersionId", "")
    if not version:
        raise ValueError("BLOCKED: S3 fence version missing")
    s3(
        "delete-object",
        "--bucket",
        c["bucket"],
        "--key",
        fence_key(c),
        "--if-match",
        actual.get("ETag", ""),
        "--expected-bucket-owner",
        c["account"],
    )
    # Ensure the marker really disappeared. If not, halt next deploy.
    fence_clear()


def read_fence(output: Path) -> dict[str, Any]:
    """Download a still-active fence only; never infer its absence from denial."""
    c = config()
    check_bucket(c)
    output.parent.mkdir(parents=True, exist_ok=True)
    s3(
        "get-object",
        "--bucket",
        c["bucket"],
        "--key",
        fence_key(c),
        "--expected-bucket-owner",
        c["account"],
        str(output),
    )
    value = strict_load(output)
    if (
        value.get("aws_account_id") != c["account"]
        or value.get("decision") != "RECONCILIATION_REQUIRED"
    ):
        raise ValueError("BLOCKED: active fence contents invalid")
    return value


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "command",
        choices=("store", "fetch", "clear-check", "mark-fence", "close-fence", "read-fence"),
    )
    p.add_argument("--phase", choices=sorted(PHASES))
    p.add_argument("--plan", type=Path)
    p.add_argument("--summary", type=Path)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--sha256")
    p.add_argument("--verified", action="store_true")
    p.add_argument("--manual", action="store_true")
    p.add_argument("--prior-run-id")
    p.add_argument("--prior-attempt")
    p.add_argument("--prior-commit")
    args = p.parse_args()
    if args.command == "store":
        if args.phase is None or args.plan is None or args.summary is None or args.output is None:
            raise ValueError("BLOCKED: store inputs missing")
        store(args.phase, args.plan, args.summary, args.output)
    elif args.command == "fetch":
        if args.phase is None or args.receipt is None or args.output is None or args.sha256 is None:
            raise ValueError("BLOCKED: fetch inputs missing")
        fetch(args.phase, args.receipt, args.output, args.sha256, args.summary)
    elif args.command == "clear-check":
        fence_clear()
    elif args.command == "read-fence":
        if args.output is None:
            raise ValueError("BLOCKED: active fence destination required")
        read_fence(args.output)
    elif args.command == "mark-fence":
        if args.phase is None or args.receipt is None or args.output is None:
            raise ValueError("BLOCKED: mark inputs missing")
        mark_fence(args.phase, args.receipt, args.output)
    else:
        if args.receipt is None or not args.verified:
            raise ValueError(
                "BLOCKED: fence closure requires independent check and explicit approval"
            )
        prior = None
        if args.manual:
            if (
                not args.prior_run_id
                or not args.prior_run_id.isdigit()
                or not args.prior_attempt
                or not args.prior_attempt.isdigit()
                or not args.prior_commit
                or not SHA.fullmatch(args.prior_commit)
            ):
                raise ValueError("BLOCKED: explicit previously failed Commit/Run/Attempt required")
            prior = {
                "commit": args.prior_commit,
                "run_id": args.prior_run_id,
                "run_attempt": args.prior_attempt,
            }
        close_fence(args.receipt, allow=True, manual_prior=prior)


if __name__ == "__main__":
    main()
