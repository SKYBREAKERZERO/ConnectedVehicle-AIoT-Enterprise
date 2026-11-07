"""Day37 durable, S3 versioned compare-and-swap fence for bootstrap/deploy.

Overlay for feat/day37-p1-audit-20261107. It intentionally does NOT replace
existing day37_plan_transport store/fetch, which own the immutable saved Plan.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
REGION = "ap-northeast-1"


class Blocked(ValueError):
    pass


def require(check: bool, reason: str) -> None:
    if not check:
        raise Blocked(reason)


def env(name: str) -> str:
    value = os.environ.get(name, "")
    require(bool(value and value != "null"), f"missing {name}")
    return value


def canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest_file(path: str | Path) -> str:
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 5_000_000, "missing/unsafe evidence")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(path: str | Path) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in pairs:
            require(k not in obj, "duplicate evidence property")
            obj[k] = v
        return obj
    digest_file(path)
    data = json.loads(Path(path).read_bytes(), object_pairs_hook=unique,
                      parse_constant=lambda v: (_ for _ in ()).throw(Blocked("nonfinite JSON")))
    require(type(data) is dict, "evidence must be JSON object")
    return data


def write(path: str | Path, value: dict[str, Any]) -> None:
    p = Path(path)
    require(not p.is_symlink(), "symlink evidence destination")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def current_identity() -> dict[str, str]:
    identity = {
        "commit": env("GITHUB_SHA"),
        "run_id": env("GITHUB_RUN_ID"),
        "run_attempt": env("GITHUB_RUN_ATTEMPT"),
        "repository": env("GITHUB_REPOSITORY"),
        "aws_account_id": env("DAY37_ACCOUNT_ID"),
        "region": REGION,
    }
    require(SHA40.fullmatch(identity["commit"]) is not None, "invalid commit")
    require(identity["repository"] == REPO, "wrong GitHub repository")
    require(re.fullmatch(r"[0-9]{12}", identity["aws_account_id"]) is not None, "invalid AWS account")
    require(all(re.fullmatch(r"[1-9][0-9]*", identity[k]) for k in ("run_id", "run_attempt")), "invalid run")
    require(os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "protected-main dispatch required")
    return identity


def identity_from_receipt(receipt: dict[str, Any], phase: str, summary_path: str,
                          release: dict[str, Any] | None = None,
                          checkpoint_path: str | None = None) -> dict[str, str]:
    """Consume the real day37_plan_transport.store() schema; no invented fields."""
    require(phase in ("bootstrap", "deploy"), "unknown phase")
    i = current_identity()
    summary = load(summary_path)
    require(receipt.get("decision") == "PRIVATE_VERSIONED_PLAN_STORED", "invalid receipt")
    for k in ("commit", "run_id", "run_attempt", "aws_account_id"):
        require(str(receipt.get(k)) == i[k], f"foreign receipt {k}")
    require(receipt.get("phase") == phase, "receipt phase mismatch")
    plan = receipt.get("plan_sha256")
    require(isinstance(plan, str) and SHA64.fullmatch(plan) is not None, "invalid plan SHA")
    require(plan == env("DAY37_APPROVED_PLAN_SHA"), "reviewed Plan SHA mismatch")
    policy = receipt.get("policy_sha256")
    require(isinstance(policy, str) and SHA64.fullmatch(policy) is not None, "policy SHA invalid")
    require(policy == digest_file(summary_path), "plan summary changed after S3 seal")
    require(summary.get("phase") == phase and summary.get("decision") == "NON_DESTRUCTIVE_TERRAFORM_PLAN", "plan policy not approved")
    image_digest = receipt.get("image_digest")
    require(image_digest == summary.get("image_digest"), "plan and summary digest mismatch")
    if phase == "deploy":
        require(isinstance(image_digest, str) and DIGEST.fullmatch(image_digest) is not None, "invalid deploy digest")
        require(release is not None and release.get("commit") == i["commit"] and
                release.get("signature_verified") is True, "untrusted ECR release")
        require(release.get("registry_digest") == image_digest, "ECR digest different from Plan")
        uri = release.get("image_uri", "")
        require(isinstance(uri, str) and uri.endswith("@" + image_digest), "mutable image URI")
        require(checkpoint_path is not None, "pre-Apply checkpoint must exist")
        cp = load(checkpoint_path)
        for k in ("commit", "run_id", "run_attempt", "aws_account_id"):
            require(str(cp.get(k)) == i[k], f"foreign checkpoint {k}")
        require(cp.get("cluster") == env("DAY37_CLUSTER") and
                cp.get("service") == env("DAY37_SERVICE"), "checkpoint targets foreign ECS")
    else:
        require(image_digest is None, "bootstrap must not target a live image")
    # Bind actual transport receipt and its immutable policy. Commit binds checked-out HCL;
    # Plan SHA binds expanded runtime Terraform inputs. This is not an attestation of reviewers.
    return {**i, "phase": phase, "plan_sha256": plan, "policy_sha256": policy,
            **({"image_digest": image_digest, "checkpoint_sha256": digest_file(checkpoint_path)}
               if phase == "deploy" else {})}


IDENTITY_KEYS = ("repository", "commit", "run_id", "run_attempt", "aws_account_id", "region",
                 "phase", "plan_sha256", "policy_sha256", "image_digest", "checkpoint_sha256")


def same(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return all(a.get(k) == b.get(k) for k in IDENTITY_KEYS)


class S3Fence:
    def __init__(self, client: Any, bucket: str, key: str, kms: str, account: str):
        self.client, self.bucket, self.key, self.kms, self.account = client, bucket, key, kms, account
        require(bool(bucket and key and kms and account), "missing S3 fence location")

    def read(self) -> tuple[dict[str, Any] | None, str | None]:
        try:
            r = self.client.get_object(Bucket=self.bucket, Key=self.key, ExpectedBucketOwner=self.account)
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                return None, None
            raise Blocked(f"S3 read cannot prove fence state: {code or type(e).__name__}") from e
        require(r.get("VersionId") not in (None, "", "null"), "S3 fence requires versioning")
        require(isinstance(r.get("ETag"), str) and bool(r["ETag"]), "missing ETag")
        try:
            d = json.loads(r["Body"].read())
        except (ValueError, TypeError) as e:
            raise Blocked("unparseable durable fence") from e
        require(type(d) is dict and d.get("schema") == 2 and d.get("state") in ("ACTIVE", "CLOSED"), "invalid fence format/state")
        return d, r["ETag"]

    def cas(self, record: dict[str, Any], prior_etag: str | None) -> None:
        kw = dict(Bucket=self.bucket, Key=self.key, Body=canonical(record), ContentType="application/json",
                  ExpectedBucketOwner=self.account, ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms)
        kw.update({"IfNoneMatch": "*"} if prior_etag is None else {"IfMatch": prior_etag})
        try:
            result = self.client.put_object(**kw)
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            raise Blocked("S3 fence conditional write failed: " + (code or type(e).__name__)) from e
        require(bool(result.get("VersionId")), "S3 write version ID missing; cannot permit Apply")

    def clear_check(self) -> None:
        d, _ = self.read()
        require(d is None or d.get("state") == "CLOSED", "ACTIVE fence; reconcile before new release")

    def mark(self, identity: dict[str, Any]) -> dict[str, Any]:
        prior, etag = self.read()
        require(prior is None or prior.get("state") == "CLOSED", "ACTIVE fence blocks overlapping Apply")
        require(prior is None or not same(prior, identity), "closed release replay blocked")
        record = {"schema": 2, "state": "ACTIVE", **identity}
        if prior is not None:
            record["previous_record_sha256"] = hashlib.sha256(canonical(prior)).hexdigest()
        self.cas(record, etag)
        actual, _ = self.read()
        require(actual == record, "fence write/readback ambiguous")
        return record

    def active(self, identity: dict[str, Any]) -> dict[str, Any]:
        record, _ = self.read()
        require(record is not None and record["state"] == "ACTIVE" and same(record, identity), "no matching ACTIVE fence")
        return record

    def close(self, identity: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
        record, etag = self.read()
        require(record is not None and record["state"] == "ACTIVE" and same(record, identity), "foreign or inactive fence")
        require(proof.get("decision") == "AWS_AND_TERRAFORM_RECONCILED" and
                proof.get("terraform_exit_code") == 0 and proof.get("live_aws_verified") is True,
                "missing independent live and zero-drift proof")
        require(proof.get("production_authorized") is False and proof.get("release_authorized") is False,
                "non-staging proof")
        require(same(proof, identity), "proof does not match active fence")
        require(etag is not None, "ETag absent")
        closed = {**record, "state": "CLOSED", "proof_sha256": hashlib.sha256(canonical(proof)).hexdigest()}
        self.cas(closed, etag)
        actual, _ = self.read()
        require(actual == closed, "fence closure readback ambiguous")
        return closed

    def recovery_check(self, checkpoint_path: str, artifact: dict[str, Any]) -> dict[str, Any]:
        cp = load(checkpoint_path)
        identity = current_identity()
        record, _ = self.read()
        require(record is not None and record["state"] == "ACTIVE" and record.get("phase") == "deploy", "no active deployment to roll back")
        for k in ("commit", "run_id", "run_attempt", "aws_account_id", "repository", "region"):
            require(record.get(k) == identity[k], "foreign recovery fence")
        require(artifact == record, "GitHub fence artifact differs from durable S3")
        require(digest_file(checkpoint_path) == record.get("checkpoint_sha256"), "checkpoint altered since pre-Apply")
        for k in ("commit", "run_id", "run_attempt", "aws_account_id"):
            require(str(cp.get(k)) == identity[k], "checkpoint wrong run/account")
        require(cp.get("cluster") == env("DAY37_CLUSTER") and cp.get("service") == env("DAY37_SERVICE"), "checkpoint wrong ECS target")
        require(cp.get("exists") is True, "no previous healthy service: manual reconciliation required")
        task = cp.get("previous_task_definition", "")
        require(isinstance(task, str) and task.startswith(f"arn:aws:ecs:{REGION}:{identity['aws_account_id']}:task-definition/cv-ota-staging"), "unsafe old Task Definition")
        require(type(cp.get("previous_desired_count")) is int and cp["previous_desired_count"] > 0, "invalid previous desired count")
        return record


def require_mark_role(phase: str) -> None:
    import boto3
    account = env("DAY37_ACCOUNT_ID")
    arn = boto3.client("sts", region_name=REGION).get_caller_identity()["Arn"]
    require(arn.startswith(f"arn:aws:sts::{account}:assumed-role/cv-ota-staging-{phase}/"),
            "only reviewed Apply Role may mark an ACTIVE fence")


def require_closure_role(phase: str) -> None:
    import boto3
    account = env("DAY37_ACCOUNT_ID")
    arn = boto3.client("sts", region_name=REGION).get_caller_identity()["Arn"]
    require(phase in ("bootstrap", "deploy"), "invalid closure phase")
    # Apply principals MUST NOT be able to certify/close their own Fence.
    require(arn.startswith(f"arn:aws:sts::{account}:assumed-role/cv-ota-staging-recovery/"),
            "only independently approved Recovery Role may close a fence")


def s3() -> S3Fence:
    import boto3
    # Reuse the actual repository's Plan transport validations, not guessed S3 settings.
    from scripts.day37_plan_transport import config, check_bucket, fence_clear
    location = config()
    check_bucket(location)
    # A legacy pre-v2 active fence MUST block new releases; migration cannot
    # silently ignore an old failed Apply. AccessDenied also blocks.
    fence_clear()
    sts = boto3.client("sts", region_name=REGION).get_caller_identity()
    require(sts["Account"] == location["account"], "STS account mismatch")
    require(sts["Arn"].startswith(f"arn:aws:sts::{location['account']}:assumed-role/"), "AWS role session required")
    return S3Fence(boto3.client("s3", region_name=REGION), location["bucket"],
                   location["prefix"] + "/recovery/active-v2.json", location["kms"], location["account"])


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("clear-check")
    rf = sub.add_parser("read-fence")
    rf.add_argument("--output", required=True)
    probe = sub.add_parser("probe")
    probe.add_argument("--fence-output", required=True)
    probe.add_argument("--status-output", required=True)
    mark = sub.add_parser("mark")
    mark.add_argument("--phase", required=True, choices=("bootstrap", "deploy"))
    mark.add_argument("--receipt", required=True)
    mark.add_argument("--summary", required=True)
    mark.add_argument("--release")
    mark.add_argument("--checkpoint")
    mark.add_argument("--output", required=True)
    close = sub.add_parser("close")
    close.add_argument("--receipt", required=True)  # S3 fence artifact
    close.add_argument("--proof", required=True)
    close.add_argument("--output", required=True)
    manual = sub.add_parser("manual-close")
    manual.add_argument("--phase", choices=("deploy", "bootstrap"), required=True)
    manual.add_argument("--fence", required=True)
    manual.add_argument("--proof", required=True)
    manual.add_argument("--output", required=True)
    check = sub.add_parser("recovery-check")
    check.add_argument("--checkpoint", required=True)
    check.add_argument("--fence", required=True)
    args = p.parse_args()
    try:
        fence = s3()
        if args.cmd == "clear-check":
            fence.clear_check()
        elif args.cmd == "read-fence":
            active, _ = fence.read()
            require(active is not None and active["state"] == "ACTIVE", "no manual reconciliation needed")
            write(args.output, active)
        elif args.cmd == "probe":
            record, _ = fence.read()
            active = record is not None and record.get("state") == "ACTIVE"
            if active:
                ident = current_identity()
                require(record.get("phase") == "deploy", "Bootstrap Fence cannot trigger ECS rollback")
                for field in ident:
                    require(record.get(field) == ident[field], "foreign active fence; manual reconciliation required")
                write(args.fence_output, record)
            write(args.status_output, {"active": "true" if active else "false",
                                       "decision": "S3_ACTIVE_DEPLOY_FENCE" if active else "NO_ACTIVE_DEPLOY_FENCE",
                                       "production_authorized": False, "release_authorized": False})
        elif args.cmd == "mark":
            require_mark_role(args.phase)
            ident = identity_from_receipt(load(args.receipt), args.phase, args.summary,
                                         load(args.release) if args.release else None, args.checkpoint)
            write(args.output, fence.mark(ident))
        elif args.cmd == "close":
            identity = load(args.receipt)
            require_closure_role(identity.get("phase", ""))
            write(args.output, fence.close(identity, load(args.proof)))
        elif args.cmd == "manual-close":
            require_closure_role(args.phase)
            record = load(args.fence)
            proof = load(args.proof)
            live, etag = fence.read()
            require(record.get("phase") == args.phase, "manual reconciliation phase mismatch")
            require(live == record and live.get("state") == "ACTIVE", "manual fence differs from S3")
            expected_decision = ("MANUAL_AWS_AND_TERRAFORM_RECONCILED" if args.phase == "deploy"
                                 else "MANUAL_BOOTSTRAP_AWS_AND_TERRAFORM_RECONCILED")
            require(proof.get("decision") == expected_decision and
                    proof.get("terraform_exit_code") == 0 and proof.get("live_aws_verified") is True,
                    "manual proof not reconciled")
            require(proof.get("production_authorized") is False and proof.get("release_authorized") is False,
                    "manual proof authorizes production")
            require(all(proof.get("prior_"+k) == record.get(k) for k in ("commit", "run_id", "run_attempt", "plan_sha256")),
                    "manual previous release mismatch")
            require(proof.get("aws_account_id") == record.get("aws_account_id") and
                    proof.get("repository") == record.get("repository"), "foreign manual reconcile")
            require(proof.get("reconciler_commit") == env("GITHUB_SHA") and
                    proof.get("reconciler_run_id") == env("GITHUB_RUN_ID") and
                    proof.get("reconciler_run_attempt") == env("GITHUB_RUN_ATTEMPT"),
                    "foreign manual reconciler")
            if args.phase == "deploy":
                require(proof.get("restored_registry_digest") == env("RECONCILE_DIGEST") and
                        DIGEST.fullmatch(proof["restored_registry_digest"]) is not None,
                        "unapproved restored ECR digest")
            else:
                require(proof.get("restored_registry_digest") is None and
                        record.get("image_digest") is None,
                        "bootstrap cannot assert a running image digest")
                require(proof.get("phase") == "bootstrap" and
                        proof.get("prior_policy_sha256") == record.get("policy_sha256"),
                        "bootstrap manual proof missing exact Plan policy binding")
            require(etag is not None, "missing active ETag")
            closed = {**record, "state": "CLOSED",
                      "proof_sha256": hashlib.sha256(canonical(proof)).hexdigest()}
            fence.cas(closed, etag)
            post, _ = fence.read()
            require(post == closed, "manual close readback ambiguous")
            write(args.output, closed)
        elif args.cmd == "recovery-check":
            fence.recovery_check(args.checkpoint, load(args.fence))
        return 0
    except (Blocked, KeyError, TypeError, OSError) as e:
        print("BLOCKED: " + str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
