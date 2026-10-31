"""Disposable LocalStack-only state version recovery and drift rehearsal.

Initial fixture Apply and deliberate state corruption/loss occur ONLY inside the
gate-owned emulator. Recovery copies one reviewed version to a DIFFERENT backend;
the damaged source is never repaired, force-unlocked, state-pushed or re-applied.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from scripts.iac.drift_policy import drift_report, reconciliation_errors
from scripts.iac.plan_admission import canonical_digest
from scripts.iac.state_integrity import recovery_errors, state_errors


def probe(
    work: Path,
    endpoint: str,
    env: dict[str, str],
    lockfile: Path,
    observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if (
        re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint) is None
        or env.get("AWS_ACCESS_KEY_ID") != "test"
        or env.get("AWS_SECRET_ACCESS_KEY") != "test"
    ):
        raise ValueError("DR probe requires isolated loopback LocalStack and dummy credentials")
    boto = importlib.import_module("boto3")
    client = boto.client(
        "s3",
        endpoint_url=endpoint,
        region_name="ap-northeast-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    prefix = "cv-day28-" + uuid4().hex[:12]
    source_bucket, target_bucket, resource_bucket = (
        prefix + s for s in ("-state", "-recovery", "-resource")
    )
    key = "ota/local/terraform.tfstate"
    for bucket in (source_bucket, target_bucket):
        client.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
        )
        client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    client.create_bucket(
        Bucket=resource_bucket, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
    )
    work.mkdir()

    def root(directory: Path, bucket: str) -> None:
        directory.mkdir()
        config = {
            "terraform": {
                "required_version": "= 1.14.7",
                "required_providers": {"aws": {"source": "hashicorp/aws", "version": ">=6.0,<7.0"}},
                "backend": {
                    "s3": {
                        "bucket": bucket,
                        "key": key,
                        "region": "ap-northeast-1",
                        "encrypt": True,
                        "use_lockfile": True,
                        "endpoints": {"s3": endpoint},
                        "skip_credentials_validation": True,
                        "skip_metadata_api_check": True,
                        "skip_requesting_account_id": True,
                        "skip_region_validation": True,
                        "use_path_style": True,
                    }
                },
            },
            "provider": {
                "aws": {
                    "region": "ap-northeast-1",
                    "access_key": "test",
                    "secret_key": "test",
                    "skip_credentials_validation": True,
                    "skip_metadata_api_check": True,
                    "skip_requesting_account_id": True,
                    "s3_use_path_style": True,
                    "endpoints": [{"s3": endpoint, "sts": endpoint, "iam": endpoint}],
                }
            },
            "resource": {
                "aws_s3_bucket_versioning": {
                    "fixture": {
                        "bucket": resource_bucket,
                        "versioning_configuration": [{"status": "Enabled"}],
                    }
                },
            },
            "output": {
                "observed_versioning": {
                    "value": (
                        "${aws_s3_bucket_versioning.fixture.versioning_configuration[0].status}"
                    )
                }
            },
        }
        (directory / "main.tf.json").write_text(json.dumps(config), encoding="utf-8")
        shutil.copy2(lockfile, directory / ".terraform.lock.hcl")
        tf(directory, "init", "-lockfile=readonly", "-input=false", "-no-color")

    def tf(
        directory: Path, *args: str, allowed: tuple[int, ...] = (0,)
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["terraform", *args], cwd=directory, env=env, capture_output=True, text=True, timeout=90
        )
        if result.returncode not in allowed:
            raise RuntimeError(
                "Isolated DR Terraform command failed: " + args[0] + ": " + result.stderr
            )
        return result

    source, restored = work / "source", work / "restored"
    root(source, source_bucket)
    # Bootstrap only these uniquely named emulator resources; never a production plan.
    tf(source, "apply", "-auto-approve", "-input=false", "-no-color")
    saved = client.get_object(Bucket=source_bucket, Key=key)
    raw = saved["Body"].read()
    parsed = json.loads(raw)
    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    )
    run_id = (
        os.environ.get("GITHUB_RUN_ID", "local") + ":" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    )
    record = {
        "account": "000000000000",
        "environment": "local",
        "bucket": source_bucket,
        "key": key,
        "version_id": saved["VersionId"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "lineage": parsed["lineage"],
        "serial": parsed["serial"],
        "commit": commit,
        "run_id": run_id,
    }
    if state_errors(raw, observed=record, expected=record, authenticate=lambda _: True):
        raise RuntimeError("Initial state integrity rejected")

    def plans(directory: Path, label: str) -> dict[str, Any]:
        codes, values = [], []
        plan_hashes: dict[str, str] = {}
        for mode, flags in (("refresh", ["-refresh-only"]), ("normal", [])):
            filename = label + "-" + mode + ".tfplan"
            result = tf(
                directory,
                "plan",
                *flags,
                "-detailed-exitcode",
                "-input=false",
                "-no-color",
                "-lock-timeout=1s",
                "-out=" + filename,
                allowed=(0, 2),
            )
            codes.append(result.returncode)
            plan_hashes[mode] = hashlib.sha256((directory / filename).read_bytes()).hexdigest()
            values.append(json.loads(tf(directory, "show", "-json", filename).stdout))
        report = drift_report(codes[0], values[0], codes[1], values[1])
        if report["decision"] == "ERROR":
            raise RuntimeError("Unclassifiable drift: " + str(report))
        return {
            "refresh_exit": codes[0],
            "normal_exit": codes[1],
            "classification": report,
            "plan_sha256": plan_hashes,
        }

    def unchanged(bucket: str, before: bytes, version: str) -> None:
        current = client.get_object(Bucket=bucket, Key=key)
        if current["VersionId"] != version or current["Body"].read() != before:
            raise RuntimeError("Read-only plans persisted State")

    def actual() -> dict[str, str]:
        status = client.get_bucket_versioning(Bucket=resource_bucket).get("Status", "MISSING")
        return {
            "resource_id": resource_bucket,
            "resource_fingerprint": canonical_digest({"versioning": status}),
        }

    clean = plans(source, "clean")
    if clean["classification"]["decision"] != "CLEAR":
        raise RuntimeError("Fixture baseline not clean")
    unchanged(source_bucket, raw, saved["VersionId"])
    expected = {**record, **actual()}
    release = {**expected, "status": "VERIFIED"}
    if reconciliation_errors(
        release=release,
        expected=expected,
        state=record,
        resource=actual(),
        drift=clean["classification"],
        authenticate=lambda _: True,
    ):
        raise RuntimeError("Clean reconciliation failed")
    client.put_bucket_versioning(
        Bucket=resource_bucket, VersioningConfiguration={"Status": "Suspended"}
    )
    drift = plans(source, "injected-drift")
    if (
        drift["classification"]["decision"] != "REVIEW_REQUIRED"
        or drift["refresh_exit"] != 2
        or drift["normal_exit"] != 2
    ):
        raise RuntimeError("Injected drift was not detected by both plans")
    unchanged(source_bucket, raw, saved["VersionId"])
    if client.get_bucket_versioning(Bucket=resource_bucket)["Status"] != "Suspended":
        raise RuntimeError("Read-only drift plans repaired a resource")
    if not reconciliation_errors(
        release=release,
        expected=expected,
        state=record,
        resource=actual(),
        drift=drift["classification"],
        authenticate=lambda _: True,
    ):
        raise RuntimeError("Drift reconciliation did not reject")

    # Deliberate fault injection only; approved historical version is retained.
    corrupt = client.put_object(
        Bucket=source_bucket, Key=key, Body=b'{"corrupt":', ServerSideEncryption="AES256"
    )
    damaged = client.get_object(Bucket=source_bucket, Key=key)["Body"].read()
    if not state_errors(
        damaged,
        observed={**record, "version_id": corrupt["VersionId"]},
        expected=record,
        authenticate=lambda _: True,
    ):
        raise RuntimeError("Corrupted state was accepted")
    deleted = client.delete_object(Bucket=source_bucket, Key=key)
    if deleted.get("DeleteMarker") is not True:
        raise RuntimeError("State-loss injection was not version-preserving")
    try:
        client.get_object(Bucket=source_bucket, Key=key)
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "NoSuchKey":
            raise
    else:
        raise RuntimeError("Missing state remained readable")
    if not state_errors(None, observed=record, expected=record, authenticate=lambda _: True):
        raise RuntimeError("Missing state was accepted")
    backup = client.get_object(Bucket=source_bucket, Key=key, VersionId=record["version_id"])[
        "Body"
    ].read()
    if state_errors(backup, observed=record, expected=record, authenticate=lambda _: True):
        raise RuntimeError("Pinned historical backup rejected")
    active = {k: record[k] for k in ("account", "environment", "bucket", "key")}
    target = {**active, "bucket": target_bucket, "disposable": True}
    now = datetime.now(UTC)
    approval = {
        "binding_sha256": canonical_digest({"record": record, "active": active, "target": target}),
        "reviewer": "independent-model-reviewer",
        "approved_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "recovery_id": prefix,
    }
    args: dict[str, Any] = {
        "record": record,
        "active": active,
        "target": target,
        "approval": approval,
        "actor": "fixture-requester",
        "now": now,
        "authenticate": lambda _: True,
    }
    if not recovery_errors(**args, lock_present=True):
        raise RuntimeError("Old lock policy bypassed")
    if recovery_errors(**args, lock_present=False):
        raise RuntimeError("Isolated model recovery rejected")
    context = {
        "source_raw": raw,
        "source_record": record,
        "source": source,
        "restored": restored,
        "target_bucket": target_bucket,
        "resource_bucket": resource_bucket,
        "key": key,
        "client": client,
        "tf": tf,
        "plans": plans,
        "source_started_at": datetime.fromtimestamp(
            (source / "clean-normal.tfplan").stat().st_mtime, UTC
        ),
    }
    if observer is not None:
        observer("before-copy", context)
    copied = client.copy_object(
        Bucket=target_bucket,
        Key=key,
        CopySource={"Bucket": source_bucket, "Key": key, "VersionId": record["version_id"]},
        ServerSideEncryption="AES256",
    )
    restored_raw = client.get_object(Bucket=target_bucket, Key=key)["Body"].read()
    target_record = {**record, "bucket": target_bucket, "version_id": copied["VersionId"]}
    if restored_raw != raw or state_errors(
        restored_raw, observed=target_record, expected=target_record, authenticate=lambda _: True
    ):
        raise RuntimeError("Restored copy differs from reviewed backup")
    root(restored, target_bucket)
    after = plans(restored, "post-restore")
    unchanged(target_bucket, raw, copied["VersionId"])
    if after["classification"]["decision"] != "REVIEW_REQUIRED":
        raise RuntimeError("Recovery silently cleared unresolved drift")
    if not reconciliation_errors(
        release={**release, "status": "INTERRUPTED"},
        expected=expected,
        state=target_record,
        resource=actual(),
        drift=after["classification"],
        authenticate=lambda _: True,
    ):
        raise RuntimeError("Interrupted release was resumed")
    listed = client.list_objects_v2(Bucket=target_bucket).get("Contents", [])
    if any(item["Key"].endswith(".tflock") for item in listed):
        raise RuntimeError("Recovery copied an old lock")
    if observer is not None:
        observer(
            "after-copy",
            {**context, "target_record": target_record, "target_raw": restored_raw, "after": after},
        )
    return {
        "status": "passed",
        "scope": "localstack-only",
        "aws_verified": False,
        "baseline": clean,
        "injected_drift": drift,
        "post_restore": after,
        "state_record": record,
        "recovered_state_record": target_record,
        "corrupt_state_denied": True,
        "missing_state_denied": True,
        "pinned_version_restored_to_isolated_copy": True,
        "read_only_plans_preserved_state": True,
        "resource_drift_not_repaired": True,
        "interrupted_release_denied": True,
        "new_request_and_approval_required": True,
        "production_apply_enabled": False,
        "automatic_restore_active_backend": False,
        "automatic_force_unlock": False,
        "independent_human_approval_exercised": False,
    }
