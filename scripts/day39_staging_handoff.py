"""Read-only, independent AWS Foundation / Credentials bootstrap handoff.

Administrator roles are distinct from GitHub deploy identities. No Terraform
Apply, database DDL, credential generation, GetSecretValue, or secret mutation.
This tool NEVER grants release authority; Day37 independently rechecks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping

REGION = "ap-northeast-1"
ACCOUNT = re.compile(r"[0-9]{12}\Z")
KMS = re.compile(r"arn:aws:kms:ap-northeast-1:([0-9]{12}):key/[a-f0-9-]+\Z")
VPC = re.compile(r"vpc-[a-f0-9]{8,17}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
EXPECTED = {
    "foundation": "cv-ota-staging-foundation-admin",
    "credentials": "cv-ota-staging-credential-admin",
}
SECRETS = {
    "application": "/connected-vehicle/staging/database/application",
    "outbox": "/connected-vehicle/staging/database/outbox",
    "remote-command": "/connected-vehicle/staging/database/remote-command",
    "redis": "/connected-vehicle/staging/redis/auth",
}
Reader = Callable[..., dict[str, Any]]


def require(ok: Any, message: str) -> None:
    if not ok:
        raise ValueError("DAY39 BLOCKED: " + message)


def validate_target(account: str, kms_arn: str, vpc: str, source: str) -> None:
    require(bool(ACCOUNT.fullmatch(account)) and account != "000000000000", "invalid account")
    match = KMS.fullmatch(kms_arn)
    require(match is not None and match.group(1) == account, "foreign/invalid data KMS key")
    require(bool(VPC.fullmatch(vpc)), "invalid VPC ID")
    require(bool(SHA.fullmatch(source)), "source SHA must be an exact commit")


def verify_checkout(source_sha: str) -> None:
    """Require the approved SHA to be the actual immutable local source."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    require(result.returncode == 0 and result.stdout.strip() == source_sha, "source SHA drift")


def aws_json(*args: str) -> dict[str, Any]:
    result = subprocess.run(
        ["aws", *args, "--region", REGION, "--output", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    require(result.returncode == 0, "AWS read-only operation failed")
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError("DAY39 BLOCKED: malformed AWS read-only response") from exc
    require(isinstance(value, dict), "unexpected AWS response")
    return value


def verify_identity(read: Reader, account: str, phase: str) -> str:
    role = EXPECTED[phase]
    actual = read("sts", "get-caller-identity")
    require(actual.get("Account") == account, "STS account mismatch")
    require(
        isinstance(actual.get("Arn"), str)
        and actual["Arn"].startswith(f"arn:aws:sts::{account}:assumed-role/{role}/"),
        "independent administrator role required",
    )
    return role


def verify_foundation(read: Reader, account: str, kms_arn: str, vpc: str) -> dict[str, Any]:
    key = read("kms", "describe-key", "--key-id", kms_arn).get("KeyMetadata", {})
    require(
        key.get("Arn") == kms_arn
        and key.get("KeyManager") == "CUSTOMER"
        and key.get("KeyState") == "Enabled"
        and key.get("KeyUsage") == "ENCRYPT_DECRYPT",
        "dedicated KMS key not active",
    )
    rows = read("ec2", "describe-vpcs", "--vpc-ids", vpc).get("Vpcs", [])
    require(
        len(rows) == 1 and rows[0].get("VpcId") == vpc and rows[0].get("State") == "available",
        "staging VPC unavailable",
    )
    databases = read(
        "rds", "describe-db-instances", "--db-instance-identifier", "cv-ota-staging-postgres"
    ).get("DBInstances", [])
    require(len(databases) == 1, "missing RDS staging instance")
    db = databases[0]
    require(
        db.get("DBInstanceStatus") == "available"
        and db.get("Engine") == "postgres"
        and str(db.get("EngineVersion", "")).startswith("17.")
        and db.get("StorageEncrypted") is True
        and db.get("MultiAZ") is True
        and db.get("PubliclyAccessible") is False
        and db.get("DeletionProtection") is True
        and db.get("DBSubnetGroup", {}).get("VpcId") == vpc,
        "RDS security/readiness contract failed",
    )
    caches = read(
        "elasticache", "describe-replication-groups", "--replication-group-id",
        "cv-ota-staging-redis",
    ).get("ReplicationGroups", [])
    require(len(caches) == 1, "missing staging Redis replication group")
    cache = caches[0]
    require(
        cache.get("Status") == "available"
        and cache.get("TransitEncryptionEnabled") is True
        and cache.get("AtRestEncryptionEnabled") is True,
        "Redis TLS/encryption/readiness contract failed",
    )
    return {"vpc_id": vpc, "rds_id": db["DBInstanceIdentifier"],
            "redis_id": cache["ReplicationGroupId"], "kms_key_arn": kms_arn}


def verify_secret(
    read: Reader, account: str, key: str, kms_arn: str, name: str
) -> dict[str, str]:
    meta = read("secretsmanager", "describe-secret", "--secret-id", name)
    arn = meta.get("ARN")
    require(
        isinstance(arn, str)
        and arn.startswith(f"arn:aws:secretsmanager:{REGION}:{account}:secret:{name}-")
        and meta.get("Name") == name
        and meta.get("KmsKeyId") == kms_arn
        and not meta.get("DeletedDate"),
        "Secret identity/KMS invalid: " + key,
    )
    stages = meta.get("VersionIdsToStages", {})
    require(
        isinstance(stages, dict)
        and len(stages) > 0
        and all(
            isinstance(labels, list)
            and all(isinstance(label, str) for label in labels)
            for labels in stages.values()
        ),
        "missing or malformed Secret versions: " + key,
    )
    require(
        sum("AWSCURRENT" in labels for labels in stages.values()) == 1
        and not any("AWSPENDING" in labels for labels in stages.values()),
        "Secret version unresolved: " + key,
    )
    rules = meta.get("RotationRules")
    require(
        meta.get("RotationEnabled") is True
        and isinstance(rules, dict)
        and (
            isinstance(rules.get("ScheduleExpression"), str)
            and bool(rules["ScheduleExpression"].strip())
            or isinstance(rules.get("AutomaticallyAfterDays"), int)
            and 1 <= rules["AutomaticallyAfterDays"] <= 90
        ),
        "automatic rotation absent: " + key,
    )
    lam = meta.get("RotationLambdaARN", "")
    require(
        isinstance(lam, str)
        and bool(re.fullmatch(
            rf"arn:aws:lambda:{REGION}:{account}:function:[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)?",
            lam,
        )),
        "Lambda rotation identity invalid: " + key,
    )
    require(bool(meta.get("LastRotatedDate")), "no actual prior rotation evidence: " + key)
    function = read("lambda", "get-function-configuration", "--function-name", lam)
    require(
        function.get("FunctionArn") == lam
        and function.get("State") == "Active"
        and function.get("LastUpdateStatus") == "Successful",
        "Lambda rotator unavailable: " + key,
    )
    return {"secret_arn": arn, "rotator_arn": lam, "rotation_observed": "metadata-only"}


def inspect(
    read: Reader, *, phase: str, account: str, kms_arn: str, vpc: str,
    source_sha: str,
) -> dict[str, Any]:
    require(phase in EXPECTED, "unknown bootstrap phase")
    validate_target(account, kms_arn, vpc, source_sha)
    role = verify_identity(read, account, phase)
    foundation = verify_foundation(read, account, kms_arn, vpc)
    output: dict[str, Any] = {
        "schema_version": "day39.staging-handoff.v1",
        "phase": phase,
        "decision": "FOUNDATION_OBSERVED" if phase == "foundation" else "CREDENTIALS_OBSERVED",
        "source_sha": source_sha,
        "aws_account_id": account,
        "region": REGION,
        "administrator_role": role,
        "foundation": foundation,
        "rotation_functionality_verified": False,
        "release_authorized": False,
        "aws_apply_executed": False,
    }
    if phase == "credentials":
        output["secrets"] = {
            key: verify_secret(read, account, key, kms_arn, name)
            for key, name in SECRETS.items()
        }
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=tuple(EXPECTED), required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--data-kms-key-arn", required=True)
    parser.add_argument("--vpc-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Use actual read-only AWS APIs")
    args = parser.parse_args()
    try:
        validate_target(args.account_id, args.data_kms_key_arn, args.vpc_id, args.source_sha)
        require(args.live, "live AWS verification not requested; cannot produce evidence")
        verify_checkout(args.source_sha)
        require(
            not any(k.startswith("AWS_ENDPOINT_URL") and v for k, v in os.environ.items()),
            "AWS endpoint override forbidden",
        )
        require(not args.output.exists() and not args.output.is_symlink(), "evidence exists")
        output = inspect(
            aws_json, phase=args.phase, account=args.account_id,
            kms_arn=args.data_kms_key_arn, vpc=args.vpc_id, source_sha=args.source_sha,
        )
        output["observed_at_utc"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as f:
            json.dump(output, f, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n")
        print("DAY39: " + output["decision"] + " (read-only, NOT RELEASE APPROVAL)")
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("DAY39 BLOCKED: " + type(exc).__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
