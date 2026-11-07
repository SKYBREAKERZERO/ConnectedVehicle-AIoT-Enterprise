from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import day37_aws as aws


@pytest.fixture(autouse=True)
def fake_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")


def test_registry_immutability_requires_real_ecr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aws, "account", lambda x: None)
    monkeypatch.setattr(
        aws,
        "aws",
        lambda *x: {
            "repositories": [
                {
                    "repositoryUri": (
                        "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/"
                        "cv-ota-staging/vehicle-api"
                    ),
                    "registryId": "123456789012",
                    "imageTagMutability": "MUTABLE",
                    "encryptionConfiguration": {"encryptionType": "AES256"},
                }
            ]
        },
    )
    with pytest.raises(ValueError, match="immutable"):
        aws.check_ecr("cv-ota-staging/vehicle-api", "123456789012")


def test_registry_manifest_bytes_must_match_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        aws,
        "aws",
        lambda *x: (
            {"imageDetails": [{"imageDigest": "sha256:" + "c" * 64}]}
            if x[1] == "describe-images"
            else {
                "images": [
                    {
                        "imageId": {"imageDigest": "sha256:" + "c" * 64},
                        "imageManifest": json.dumps({"config": {"digest": "sha256:" + "b" * 64}}),
                    }
                ],
                "failures": [],
            }
        ),
    )
    with pytest.raises(ValueError, match="manifest bytes"):
        aws.read_manifest("cv-ota-staging/vehicle-api", "tag", "123456789012")


def test_release_record_must_bind_same_attempt(tmp_path: Path) -> None:
    p = tmp_path / "release.json"
    p.write_text(json.dumps({"commit": "a" * 40, "run_id": "123", "run_attempt": "9"}))
    with pytest.raises(ValueError, match="Run/Attempt"):
        aws.verify_release(p, "123456789012", "cv-ota-staging/vehicle-api", tmp_path / "out.json")


def test_recovery_blocks_foreign_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAY37_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("DAY37_CLUSTER", "cv-ota-staging")
    monkeypatch.setenv("DAY37_SERVICE", "cv-ota-staging-api")
    p = tmp_path / "checkpoint.json"
    p.write_text(
        json.dumps(
            {
                "commit": "a" * 40,
                "run_id": "123",
                "run_attempt": "1",
                "aws_account_id": "999999999999",
                "cluster": "prod",
                "service": "other",
                "exists": True,
            }
        )
    )
    with pytest.raises(ValueError, match="unapproved"):
        aws.recover(p, tmp_path / "recovery.json")


def test_no_healthy_baseline_means_manual_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DAY37_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("DAY37_CLUSTER", "cv-ota-staging")
    monkeypatch.setenv("DAY37_SERVICE", "cv-ota-staging-api")
    monkeypatch.setattr(aws, "account", lambda _: None)
    p = tmp_path / "checkpoint.json"
    p.write_text(
        json.dumps(
            {
                "commit": "a" * 40,
                "run_id": "123",
                "run_attempt": "1",
                "aws_account_id": "123456789012",
                "cluster": "cv-ota-staging",
                "service": "cv-ota-staging-api",
                "exists": False,
            }
        )
    )
    with pytest.raises(ValueError, match="manual recovery"):
        aws.recover(p, tmp_path / "recovery.json")


def test_command_does_not_expose_sensitive_subprocess_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        aws.subprocess,
        "run",
        lambda *a, **k: Mock(returncode=1, stdout="token", stderr="secret-response"),
    )
    with pytest.raises(ValueError) as error:
        aws.command(["aws", "sts", "get-caller-identity"])
    assert "token" not in str(error.value) and "secret-response" not in str(error.value)
