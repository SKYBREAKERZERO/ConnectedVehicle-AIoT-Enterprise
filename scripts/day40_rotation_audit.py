"""Collect read-only Day40 prerequisites. This command never grants release authority."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day37_preflight import REGION, REPOSITORY, require_rotated_secret

SECRETS = {
    "application": "/connected-vehicle/staging/database/application",
    "redis": "/connected-vehicle/staging/redis/auth",
}
SECRET_METADATA = (
    "{ARN:ARN,DeletedDate:DeletedDate,RotationEnabled:RotationEnabled,"
    "RotationLambdaARN:RotationLambdaARN,RotationRules:RotationRules,"
    "LastRotatedDate:LastRotatedDate,VersionIdsToStages:VersionIdsToStages}"
)
DENIED = re.compile(r"\b(?:AccessDeniedException|AccessDenied|UnauthorizedOperation)\b")


class AuditUnavailable(ValueError):
    pass


def aws(*args: str) -> Any:
    try:
        result = subprocess.run(
            [
                "aws",
                *args,
                "--region",
                REGION,
                "--output",
                "json",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "8",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_MAX_ATTEMPTS": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditUnavailable("UNREACHABLE") from exc
    if result.returncode:
        status = "ACCESS_DENIED" if DENIED.search(result.stderr) else "UNAVAILABLE"
        raise AuditUnavailable(status)
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise AuditUnavailable("INVALID_METADATA") from exc


def collect(account: str) -> dict[str, Any]:
    candidate = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    report: dict[str, Any] = {
        "repository": REPOSITORY,
        "candidate_sha": candidate,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "observed_at": datetime.now(UTC).isoformat(),
        "account": account,
        "region": REGION,
        "decision": "BLOCKED",
        "aws_rotation_verified": False,
        "release_authorized": False,
        "checks": {},
    }
    checks = report["checks"]
    if os.environ.get("GITHUB_ACTIONS") == "true" and (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_SHA") != candidate
        or not re.fullmatch("[1-9][0-9]*", os.environ.get("GITHUB_RUN_ID", ""))
        or not re.fullmatch("[1-9][0-9]*", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    ):
        checks["source"] = "CI_SOURCE_MISMATCH"
        return report
    try:
        caller = aws("sts", "get-caller-identity", "--query", "Account")
    except AuditUnavailable as exc:
        checks["account"] = str(exc)
        return report
    if caller != account:
        checks["account"] = "ACCOUNT_MISMATCH"
        return report
    checks["account"] = "MATCH"

    for kind, path in SECRETS.items():
        try:
            secret = aws(
                "secretsmanager", "describe-secret", "--secret-id", path, "--query", SECRET_METADATA
            )
            arn = secret["ARN"]
            if not re.fullmatch(
                rf"arn:aws:secretsmanager:{REGION}:{account}:secret:{path}-[A-Za-z0-9]{{6}}", arn
            ):
                raise ValueError("Invalid ARN")
            if not isinstance(secret.get("VersionIdsToStages"), dict) or not isinstance(
                secret.get("RotationRules"), dict
            ):
                raise ValueError("Malformed rotation metadata")
            require_rotated_secret(secret, arn, account, kind)
            checks[f"{kind}_secret"] = {
                "status": "ROTATION_METADATA_OBSERVED",
                "arn": arn,
                "lambda_version_arn": secret["RotationLambdaARN"],
                "current_version_id": next(
                    key
                    for key, stages in secret["VersionIdsToStages"].items()
                    if "AWSCURRENT" in stages
                ),
            }
        except AuditUnavailable as exc:
            checks[f"{kind}_secret"] = str(exc)
        except (ValueError, KeyError, TypeError):
            checks[f"{kind}_secret"] = "ROTATION_METADATA_NOT_VERIFIED"

        try:
            versions = aws(
                "lambda",
                "list-versions-by-function",
                "--function-name",
                f"cv-ota-staging-rotate-{kind}",
                "--query",
                "Versions[].Version",
            )
            expected = checks[f"{kind}_secret"]
            if (
                isinstance(expected, dict)
                and isinstance(versions, list)
                and expected["lambda_version_arn"].rsplit(":", 1)[1] in versions
            ):
                checks[f"{kind}_lambda"] = "BOUND_VERSION_OBSERVED"
            else:
                checks[f"{kind}_lambda"] = "BOUND_VERSION_NOT_VERIFIED"
        except AuditUnavailable as exc:
            checks[f"{kind}_lambda"] = str(exc)

    for service, command, id_arg, name, query in (
        (
            "rds",
            "describe-db-instances",
            "--db-instance-identifier",
            "cv-ota-staging-postgres",
            "DBInstances[].DBInstanceStatus",
        ),
        (
            "elasticache",
            "describe-replication-groups",
            "--replication-group-id",
            "cv-ota-staging-redis",
            "ReplicationGroups[].Status",
        ),
    ):
        try:
            states = aws(service, command, id_arg, name, "--query", query)
            checks[service] = "AVAILABLE" if states == ["available"] else "NOT_READY"
        except AuditUnavailable as exc:
            checks[service] = str(exc)
    checks["live_rotation_and_client_continuity"] = "NOT_EXECUTED"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]{12}", args.account) or args.account == "000000000000":
        parser.error("An explicit staging account ID is required")
    report = collect(args.account)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
