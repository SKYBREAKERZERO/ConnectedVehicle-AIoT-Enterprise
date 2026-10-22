from __future__ import annotations

from copy import deepcopy
from datetime import date
from typing import Any

import pytest

from scripts.iac.scan_policy import audit


@pytest.fixture
def scan() -> dict[str, Any]:
    return {
        "check_type": "terraform",
        "summary": {"passed": 1, "failed": 0, "skipped": 0, "parsing_errors": 0},
        "results": {"passed_checks": [{}], "failed_checks": [], "skipped_checks": []},
    }


def test_clean_scan_passes(scan: dict[str, Any]) -> None:
    assert not audit(scan, {"exceptions": []})


@pytest.mark.parametrize("failure", ["parsing_errors", "skipped", "zero_checks"])
def test_scanner_cannot_silently_skip_failures(scan: dict[str, Any], failure: str) -> None:
    if failure == "zero_checks":
        scan["summary"]["passed"] = 0
    else:
        scan["summary"][failure] = 1
    assert audit(scan, {"exceptions": []})


def test_no_waiver_for_wildcard_or_encryption_scan(scan: dict[str, Any]) -> None:
    exceptions = {
        "exceptions": [
            {
                "check_id": "CKV_AWS_356",
                "resource": "aws_iam_policy.this",
                "file": "main.tf",
                "expires": "2099-01-01",
                "reason": "skip",
            }
        ]
    }
    assert audit(scan, exceptions)


def test_exception_matches_check_resource_file_caller_and_expiry(scan: dict[str, Any]) -> None:
    finding = {
        "check_id": "CKV_AWS_61",
        "resource": "module.secret_bootstrap_role.aws_iam_role.this",
        "file_path": "/modules/security/iam-role/main.tf",
        "caller_file_path": "/environments/local/main.tf",
    }
    scan["summary"]["failed"] = 1
    scan["results"]["failed_checks"] = [finding]
    exceptions = {
        "exceptions": [
            {
                "check_id": finding["check_id"],
                "resource": finding["resource"],
                "file": finding["file_path"].lstrip("/"),
                "expires": "2027-01-01",
                "reason": "specific reviewed constraint",
            }
        ]
    }
    assert not audit(scan, exceptions, today=date(2026, 10, 9))
    assert audit(scan, exceptions, today=date(2027, 1, 2))
    for key in ("check_id", "resource", "file_path", "caller_file_path"):
        changed = deepcopy(scan)
        changed["results"]["failed_checks"][0][key] = "unapproved"
        assert audit(changed, exceptions, today=date(2026, 10, 9))


def test_corrupt_report_never_passes() -> None:
    assert audit([], {"exceptions": []})
    assert audit({}, {"exceptions": []})


@pytest.mark.parametrize("environment", ["prod", "dev", None])
def test_local_s3_operational_waiver_cannot_escape_scope(
    scan: dict[str, Any], environment: str | None
) -> None:
    finding: dict[str, Any] = {
        "check_id": "CKV_AWS_18",
        "resource": "module.artifact_bucket.aws_s3_bucket.this",
        "file_path": "/modules/ota-artifact-bucket/main.tf",
        "entity_tags": {"Environment": environment},
    }
    scan["results"]["failed_checks"] = [finding]
    exceptions = {
        "exceptions": [
            {
                "check_id": finding["check_id"],
                "resource": finding["resource"],
                "file": "modules/ota-artifact-bucket/main.tf",
                "scope": "local-only",
                "expires": "2026-11-18",
                "reason": "Local delivery gap",
            }
        ]
    }
    assert audit(scan, exceptions, today=date(2026, 10, 19))
    finding["entity_tags"]["Environment"] = "local"
    assert not audit(scan, exceptions, today=date(2026, 10, 19))
