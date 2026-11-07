"""Kill a real Terraform Plan process holding an emulator S3 backend lock.

No Apply or automatic unlock. The enclosing isolated container owns cleanup.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from uuid import uuid4


def probe(root: Path, endpoint: str, env: dict[str, str]) -> dict[str, Any]:
    if (
        re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint) is None
        or env.get("AWS_ACCESS_KEY_ID") != "test"
        or env.get("AWS_SECRET_ACCESS_KEY") != "test"
    ):
        raise ValueError("Failure probe requires isolated loopback emulator and dummy credentials")
    boto = importlib.import_module("boto3")
    config = importlib.import_module("botocore.config").Config(
        connect_timeout=2, read_timeout=2, retries={"max_attempts": 0}
    )
    client = boto.client(
        "s3",
        endpoint_url=endpoint,
        region_name="ap-northeast-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=config,
    )
    bucket = "cv-day27-" + uuid4().hex[:12]
    client.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
    )
    state_key = "probe/terraform.tfstate"
    state = json.dumps(
        {
            "version": 4,
            "terraform_version": "1.14.7",
            "serial": 7,
            "lineage": str(uuid4()),
            "outputs": {},
            "resources": [],
        }
    ).encode()
    client.put_object(Bucket=bucket, Key=state_key, Body=state, ServerSideEncryption="AES256")
    root.mkdir()
    (root / "main.tf.json").write_text(
        json.dumps(
            {
                "terraform": {
                    "backend": {
                        "s3": {
                            "bucket": bucket,
                            "key": state_key,
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
                # Bounded, built-in-only graph produces enough output to keep the plan
                # process alive while the parent observes the native lock. No provider download.
                "resource": {
                    "terraform_data": {"probe": {"count": 2000, "input": "offline-lock-holder"}}
                },
            }
        ),
        encoding="utf-8",
    )
    initialized = subprocess.run(
        ["terraform", "init", "-input=false", "-no-color"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if initialized.returncode:
        raise RuntimeError("Failure-probe init failed: " + initialized.stderr)
    process = subprocess.Popen(
        ["terraform", "plan", "-input=false", "-refresh=false", "-no-color", "-lock-timeout=1s"],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    lock_key = state_key + ".tflock"
    try:
        deadline = time.monotonic() + 20
        lock = b""
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Holder exited before lock observation")
            try:
                lock = client.get_object(Bucket=bucket, Key=lock_key)["Body"].read()
                break
            except Exception as exc:
                if getattr(exc, "response", {}).get("Error", {}).get("Code") != "NoSuchKey":
                    raise
            time.sleep(0.05)
        if not lock:
            raise RuntimeError("Native holder lock observation timed out")
        lock_id = json.loads(lock)["ID"]

        def contender() -> float:
            started = time.monotonic()
            result = subprocess.run(
                ["terraform", "plan", "-input=false", "-no-color", "-lock-timeout=1s"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            elapsed = time.monotonic() - started
            if (
                result.returncode == 0
                or "Error acquiring the state lock" not in result.stderr
                or lock_id not in result.stderr
                or elapsed > 10
            ):
                raise RuntimeError(
                    "Concurrent/interrupted contender failed to reject within bounds"
                )
            if client.get_object(Bucket=bucket, Key=lock_key)["Body"].read() != lock:
                raise RuntimeError("Contender changed holder lock")
            return round(elapsed, 3)

        live_wait = contender()
        # Abrupt termination, not graceful SIGINT; outcome is deliberately ambiguous.
        process.kill()
        process.communicate(timeout=10)
        killed_wait = contender()
        if client.get_object(Bucket=bucket, Key=state_key)["Body"].read() != state:
            raise RuntimeError("Plan or recovery attempt changed state")
        if client.get_object(Bucket=bucket, Key=lock_key)["Body"].read() != lock:
            raise RuntimeError("Orphaned native lock was automatically removed")
        return {
            "status": "passed",
            "localstack_only": True,
            "aws_verified": False,
            "holder_process_killed": True,
            "live_contender_wait_seconds": live_wait,
            "orphan_contender_wait_seconds": killed_wait,
            "orphan_lock_retained": True,
            "state_sha256": hashlib.sha256(state).hexdigest(),
            "state_unchanged": True,
            "automatic_force_unlock": False,
            "apply_performed": False,
        }
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        # No delete_object, state restore or force-unlock. The gate destroys only
        # its own disposable LocalStack container after collecting evidence.
