"""Offline adversarial tests for encrypted/private versioned S3 plan handoff."""

from __future__ import annotations

from typing import Any

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import day37_plan_transport as t


@pytest.fixture(autouse=True)
def context(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "DAY37_ACCOUNT_ID": "123456789012",
        "DAY37_PLAN_BUCKET": "cv-ota-staging-plan-bucket",
        "DAY37_PLAN_PREFIX": "connected-vehicle/day37-plans/v1",
        "DAY37_PLAN_KMS_ARN": "arn:aws:kms:ap-northeast-1:123456789012:key/abc",
        "DAY37_BACKEND_KMS_ARN": "arn:aws:kms:ap-northeast-1:123456789012:key/abc",
    }.items():
        monkeypatch.setenv(k, v)


def receipt(phase: str, body: bytes) -> dict[str, Any]:
    i, c = t.identity(), t.config()
    return {
        **i,
        "phase": phase,
        "aws_account_id": c["account"],
        "bucket": c["bucket"],
        "object_key": t.key(phase, c, i),
        "version_id": "version-1",
        "kms_key_arn": c["kms"],
        "plan_sha256": hashlib.sha256(body).hexdigest(),
        "plan_bytes": len(body),
        "created_at": datetime.now(UTC).isoformat(),
        "decision": "PRIVATE_VERSIONED_PLAN_STORED",
    }


def test_upload_is_versioned_sse_kms_and_no_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"binary Terraform Plan: private"
    path = tmp_path / "plan.tfplan"
    path.write_bytes(body)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"decision": "NON_DESTRUCTIVE_TERRAFORM_PLAN"}))
    monkeypatch.setattr(t, "check_bucket", lambda _: None)
    calls: list[tuple[str, ...]] = []

    def fake(*args: str) -> dict[str, str]:
        calls.append(args)
        return {"VersionId": "v-1"}

    monkeypatch.setattr(t, "s3", fake)
    row = t.store("deploy", path, policy, tmp_path / "receipt.json")
    assert row["plan_sha256"] == hashlib.sha256(body).hexdigest()
    assert "--if-none-match" in calls[0] and "aws:kms" in calls[0]
    assert "deploy.tfplan" in row["object_key"]
    assert row["release_authorized"] is False


def test_receipt_cannot_be_spliced_across_run_or_phase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"demo"
    p = tmp_path / "receipt.json"
    p.write_text(json.dumps(receipt("bootstrap", body)))
    monkeypatch.setattr(t, "check_bucket", lambda _: None)
    with pytest.raises(ValueError, match="phase"):
        t.fetch("deploy", p, tmp_path / "secret.tfplan", hashlib.sha256(body).hexdigest())
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    with pytest.raises(ValueError, match="receipt belongs"):
        t.fetch("bootstrap", p, tmp_path / "secret.tfplan", hashlib.sha256(body).hexdigest())


def test_wrong_approved_sha_blocks_before_s3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "receipt.json"
    p.write_text(json.dumps(receipt("deploy", b"demo")))
    monkeypatch.setattr(t, "check_bucket", lambda _: None)
    monkeypatch.setattr(t, "s3", lambda *x: pytest.fail("must not fetch wrong approved digest"))
    with pytest.raises(ValueError, match="reviewer-approved"):
        t.fetch("deploy", p, tmp_path / "plan", "0" * 64)


def test_s3_tampered_bytes_deleted_and_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = b"exact approved plan"
    bad = b"wrong plan contents"
    p = tmp_path / "receipt.json"
    p.write_text(json.dumps(receipt("deploy", good)))
    monkeypatch.setattr(t, "check_bucket", lambda _: None)

    def fake(*args: str) -> dict[str, str]:
        Path(args[-1]).write_bytes(bad)
        return {"VersionId": "version-1"}

    monkeypatch.setattr(t, "s3", fake)
    target = tmp_path / "private.plan"
    with pytest.raises(ValueError, match="exact approved"):
        t.fetch("deploy", p, target, hashlib.sha256(good).hexdigest())
    assert not target.exists()


def test_access_denied_is_not_fence_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(t, "check_bucket", lambda _: None)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: Mock(returncode=255, stderr="AccessDenied")
    )
    with pytest.raises(ValueError, match="cannot prove absence"):
        t.fence_clear()


def test_active_fence_prevents_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(t, "check_bucket", lambda _: None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Mock(returncode=0, stderr=""))
    with pytest.raises(ValueError, match="unresolved"):
        t.fence_clear()


def test_fence_written_before_apply_and_immutable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r = tmp_path / "receipt.json"
    r.write_text(json.dumps(receipt("deploy", b"demo")))
    monkeypatch.setattr(t, "fence_clear", lambda: None)
    seen: list[tuple[str, ...]] = []
    monkeypatch.setattr(t, "s3", lambda *a: seen.append(a) or {"VersionId": "v1"})
    t.mark_fence("deploy", r, tmp_path / "fence.json")
    assert "--if-none-match" in seen[0]
    assert (
        json.loads((tmp_path / "fence.json").read_text())["decision"] == "RECONCILIATION_REQUIRED"
    )


def test_plan_bucket_rejects_foreign_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAY37_PLAN_KMS_ARN", "arn:aws:kms:ap-northeast-1:999999999999:key/foreign")
    with pytest.raises(ValueError, match="KMS key"):
        t.config()
