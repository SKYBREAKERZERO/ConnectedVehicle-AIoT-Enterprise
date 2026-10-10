"""Audit Checkov JSON: no soft-fail, inline skips, parsing errors or global waivers."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any


def audit(report: Any, exceptions: dict[str, Any], *, today: date | None = None) -> list[str]:
    today = today or date.today()
    allowed = {}
    for exception in exceptions["exceptions"]:
        identity = (exception["check_id"], exception["resource"], exception["file"])
        if identity in allowed or not exception["reason"].strip():
            return ["Invalid or duplicate scanner exception"]
        # Exceptions apply only to the known local root's narrowly named resources.
        if exception["check_id"] not in {"CKV_AWS_61", "CKV2_AWS_57"}:
            return ["Exceptions for dangerous-change/IAM/encryption checks are prohibited"]
        if date.fromisoformat(exception["expires"]) < today:
            return [f"Expired scanner exception: {exception['check_id']} {exception['resource']}"]
        allowed[identity] = exception
    reports = report if isinstance(report, list) else [report]
    errors = []
    checks = 0
    for entry in reports:
        if not isinstance(entry, dict) or entry.get("check_type") != "terraform":
            errors.append("Missing or unsupported Checkov report")
            continue
        results = entry.get("results", {})
        summary = entry.get("summary", {})
        checks += summary.get("passed", 0) + summary.get("failed", 0)
        if summary.get("parsing_errors", 0) or results.get("parsing_errors"):
            errors.append("Checkov Terraform parsing errors")
        if results.get("skipped_checks") or summary.get("skipped", 0):
            errors.append("Checkov inline skips/unchecked resources are prohibited")
        for finding in results.get("failed_checks", []):
            path = finding["file_path"].replace("\\", "/").lstrip("/")
            identity = (finding["check_id"], finding["resource"], path)
            # Caller metadata binds a module finding to the local deployment.
            callers = finding.get("caller_file_path", "") or ""
            callers = callers.replace("\\", "/")
            local_secret = (
                finding["check_id"] == "CKV2_AWS_57"
                and finding.get("entity_tags", {}).get("Environment") == "local"
                and finding.get("check_result", {})
                .get("entity", {})
                .get("aws_secretsmanager_secret", {})
                .get("this", {})
                .get("name", [""])[0]
                in {
                    "/connected-vehicle/local/database/application",
                    "/connected-vehicle/local/database/outbox",
                    "/connected-vehicle/local/database/remote-command",
                }
            )
            if identity in allowed and (
                callers.endswith("/environments/local/main.tf") or local_secret
            ):
                continue
            errors.append(f"{finding['check_id']} {finding['resource']} ({path})")
    if checks == 0:
        errors.append("Scanner executed zero checks")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--exceptions", type=Path, default=Path(__file__).with_name("scan_exceptions.json")
    )
    args = parser.parse_args()
    try:
        issues = audit(
            json.loads(args.report.read_text(encoding="utf-8-sig")),
            json.loads(args.exceptions.read_text(encoding="utf-8")),
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        issues = ["Invalid scanner report/exception configuration (fail closed)"]
    for issue in issues:
        print(issue)
    print(f"Security scan: {'FAIL' if issues else 'PASS'} ({len(issues)} violations)")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
