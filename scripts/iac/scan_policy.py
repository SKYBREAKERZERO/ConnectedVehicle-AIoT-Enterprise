"""Audit Checkov JSON: no soft-fail, inline skips, parsing errors or global waivers."""

from __future__ import annotations

import argparse
import importlib
import json
from datetime import date
from pathlib import Path
from typing import Any

LOCAL_OPERATIONAL_EXCEPTIONS = {
    (check, resource, path)
    for check in ("CKV_AWS_18", "CKV_AWS_144", "CKV2_AWS_62")
    for resource, path in (
        ("aws_s3_bucket.state", "bootstrap/state-backend/main.tf"),
        ("module.artifact_bucket.aws_s3_bucket.this", "modules/ota-artifact-bucket/main.tf"),
    )
} | {
    (
        "CKV2_AWS_57",
        "module.ota_authority.aws_secretsmanager_secret.this",
        "modules/ota-secrets/main.tf",
    )
}


# Checkov 3.3.26's CKV_AWS_31 predates the Terraform AWS provider's
# write-only ElastiCache auth_token_wo attribute. A proof against actual HCL,
# rather than a Checkov skip, is allowed for precisely this staging resource.
REDIS_WO_COMPATIBILITY = (
    "CKV_AWS_31",
    "aws_elasticache_replication_group.redis",
    "environments/ota-staging-foundation/main.tf",
)


def _one(value: Any) -> Any:
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("Ambiguous HCL field; expected exactly one value")
        return value[0]
    return value


def _redis_wo_proven(root: Path) -> bool:
    """Compensating source-based control; any uncertainty is a scan failure."""
    try:
        base = root.resolve(strict=True)
        path = base / REDIS_WO_COMPATIBILITY[2]
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(base):
            return False
        hcl2 = importlib.import_module("hcl2")
        with path.open(encoding="utf-8") as src:
            parsed = hcl2.load(src)
        matching: list[dict[str, Any]] = []
        for resource in parsed.get("resource", []):
            for nested in resource.get("aws_elasticache_replication_group", []):
                if "redis" in nested:
                    matching.append(_one(nested["redis"]))
        if len(matching) != 1 or not isinstance(matching[0], dict):
            return False
        attrs = matching[0]
        if "auth_token" in attrs or "user_group_ids" in attrs:
            return False
        required: dict[str, str] = {
            "auth_token_wo": "${var.redis_auth_token}",
            "auth_token_wo_version": "${var.redis_token_version}",
            "kms_key_id": "${var.data_kms_key_arn}",
        }
        if any(_one(attrs.get(key)) != value for key, value in required.items()):
            return False
        if any(
            _one(attrs.get(key)) is not True
            for key in ("transit_encryption_enabled", "at_rest_encryption_enabled")
        ):
            return False
        tokens = [
            _one(v["redis_auth_token"])
            for v in parsed.get("variable", [])
            if "redis_auth_token" in v
        ]
        if len(tokens) != 1 or not isinstance(tokens[0], dict):
            return False
        return all(_one(tokens[0].get(key)) is True for key in ("ephemeral", "sensitive"))
    except Exception:
        # A parser failure or missing source must never authorize an exemption.
        return False


def audit(
    report: Any,
    exceptions: dict[str, Any],
    *,
    today: date | None = None,
    source_root: Path | None = None,
) -> list[str]:
    today = today or date.today()
    allowed = {}
    for exception in exceptions["exceptions"]:
        identity = (exception["check_id"], exception["resource"], exception["file"])
        if identity in allowed or not exception["reason"].strip():
            return ["Invalid or duplicate scanner exception"]
        # Exceptions apply only to the known local root's narrowly named resources.
        if exception["check_id"] not in {"CKV_AWS_61", "CKV2_AWS_57"} and (
            identity not in LOCAL_OPERATIONAL_EXCEPTIONS or exception.get("scope") != "local-only"
        ):
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
            # Checkov may emit entity_tags: null. Without local metadata,
            # no local-only security exception is authorized.
            raw_tags = finding.get("entity_tags")
            if raw_tags is not None and not isinstance(raw_tags, dict):
                errors.append("Invalid Checkov resource tag metadata")
                continue
            tags = raw_tags if raw_tags is not None else {}
            path = finding["file_path"].replace("\\", "/").lstrip("/")
            identity = (finding["check_id"], finding["resource"], path)
            if (
                identity == REDIS_WO_COMPATIBILITY
                and not finding.get("caller_file_path")
                and source_root is not None
                and _redis_wo_proven(source_root)
            ):
                print("CKV_AWS_31: equivalent write-only TLS Redis control verified from HCL")
                continue
            # Caller metadata binds a module finding to the local deployment.
            callers = finding.get("caller_file_path", "") or ""
            callers = callers.replace("\\", "/")
            local_secret = (
                finding["check_id"] == "CKV2_AWS_57"
                and tags.get("Environment") == "local"
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
            local_operational = (
                identity in LOCAL_OPERATIONAL_EXCEPTIONS
                and allowed.get(identity, {}).get("scope") == "local-only"
                and tags.get("Environment") == "local"
            )
            if identity in allowed and (
                callers.endswith("/environments/local/main.tf") or local_secret or local_operational
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
