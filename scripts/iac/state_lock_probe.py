"""Exercise Terraform's native S3 lock protocol only against an isolated emulator."""

from __future__ import annotations

import importlib
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from uuid import uuid4


def probe(root: Path, endpoint: str, env: dict[str, str]) -> dict[str, Any]:
    if re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint) is None:
        raise ValueError("Lock probe permits only ephemeral loopback LocalStack")
    if env.get("AWS_ACCESS_KEY_ID") != "test" or env.get("AWS_SECRET_ACCESS_KEY") != "test":
        raise ValueError("Lock probe requires isolated dummy credentials")
    boto3 = importlib.import_module("boto3")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="ap-northeast-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    bucket = "cv-lock-probe-" + uuid4().hex[:12]
    client.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
    )
    root.mkdir()
    config = {
        "terraform": {
            "backend": {
                "s3": {
                    "bucket": bucket,
                    "key": "probe/terraform.tfstate",
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
            }
        },
        "resource": {"terraform_data": {"probe": {"input": "lock-only-contract"}}},
    }
    (root / "main.tf.json").write_text(json.dumps(config), encoding="utf-8")

    def terraform(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["terraform", *args], cwd=root, env=env, text=True, capture_output=True, timeout=30
        )

    initialized = terraform("init", "-input=false", "-no-color")
    if initialized.returncode:
        raise RuntimeError("Emulator lock probe initialization failed: " + initialized.stderr)
    lock_id = str(uuid4())
    lock = json.dumps(
        {
            "ID": lock_id,
            "Operation": "OperationTypePlan",
            "Info": "Day26 contention fixture",
            "Who": "isolated-test",
            "Version": "1.14.7",
            "Created": "2026-10-27T00:00:00Z",
            "Path": bucket + "/probe/terraform.tfstate",
        }
    ).encode()
    key = "probe/terraform.tfstate.tflock"
    client.put_object(
        Bucket=bucket, Key=key, Body=lock, ServerSideEncryption="AES256", IfNoneMatch="*"
    )
    started = time.monotonic()
    blocked = terraform("plan", "-input=false", "-no-color", "-lock-timeout=1s")
    elapsed = time.monotonic() - started
    if (
        blocked.returncode == 0
        or "Error acquiring the state lock" not in blocked.stderr
        or lock_id not in blocked.stderr
        or elapsed > 15
    ):
        raise RuntimeError("Native S3 contention did not fail closed within bounds")
    if client.get_object(Bucket=bucket, Key=key)["Body"].read() != lock:
        raise RuntimeError("Contender overwrote another holder's lock")
    # Delete only the fixture's own known lock; never force-unlock a shared backend.
    client.delete_object(Bucket=bucket, Key=key)
    unblocked = terraform("plan", "-input=false", "-no-color", "-lock-timeout=1s")
    if unblocked.returncode or "1 to add" not in unblocked.stdout:
        raise RuntimeError("Native lock release/reacquisition failed: " + unblocked.stderr)
    if client.list_objects_v2(Bucket=bucket).get("KeyCount") != 0:
        raise RuntimeError("Read-only plan leaked a lock or wrote state")
    client.delete_bucket(Bucket=bucket)
    return {
        "status": "passed",
        "implementation": "terraform-s3-use_lockfile",
        "localstack_only": True,
        "aws_verified": False,
        "blocked_wait_seconds": round(elapsed, 3),
        "holder_preserved": True,
        "release_reacquire": True,
    }
