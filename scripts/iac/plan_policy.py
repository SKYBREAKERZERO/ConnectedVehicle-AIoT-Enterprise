"""Fail-closed Terraform JSON plan policies (standard library only)."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

Plan = dict[str, Any]

POLICY_FIELDS = {
    "aws_iam_policy": "policy",
    "aws_iam_role_policy": "policy",
    "aws_iam_user_policy": "policy",
    "aws_iam_group_policy": "policy",
    "aws_iam_role": "assume_role_policy",
    "aws_kms_key": "policy",
    "aws_sqs_queue_policy": "policy",
    "aws_sns_topic_policy": "policy",
    "aws_secretsmanager_secret_policy": "policy",
    "aws_s3_bucket_policy": "policy",
}
ENCRYPTION_FIELDS = {
    "aws_secretsmanager_secret": "kms_key_id",
    "aws_sns_topic": "kms_master_key_id",
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
}
SUPPORTED_TYPES = (
    set(POLICY_FIELDS)
    | set(ENCRYPTION_FIELDS)
    | {
        "aws_sqs_queue",
        "aws_kms_alias",
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_sqs_queue_redrive_policy",
        "aws_sqs_queue_redrive_allow_policy",
        "aws_s3_bucket",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_dynamodb_table",
    }
)
VALID_ACTIONS = {
    ("no-op",),
    ("create",),
    ("read",),
    ("update",),
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
    ("forget",),
}


def resources(module: Plan) -> Iterator[Plan]:
    for resource in module.get("resources", []):
        if resource.get("mode", "managed") == "managed":
            yield resource
    for child in module.get("child_modules", []):
        yield from resources(child)


def strings(value: Any) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) and v for v in value):
        return value
    raise ValueError("missing or malformed policy field")


def wildcard(value: Any) -> bool:
    if isinstance(value, str):
        return "*" in value or "?" in value
    if isinstance(value, list):
        return any(wildcard(v) for v in value)
    if isinstance(value, dict):
        return any(wildcard(v) for v in value.values())
    return False


def policy_errors(raw: Any, *, trust: bool = False, kms_account: str | None = None) -> list[str]:
    """No broad Allow policies; Deny wildcards do not grant access."""
    errors = []
    try:
        policy = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(policy, dict):
            raise ValueError("invalid policy")
        statements = policy["Statement"]
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list) or not statements:
            raise ValueError("empty statements")
        for statement in statements:
            if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
                raise ValueError("invalid statement")
            if statement["Effect"] == "Deny":
                continue
            if any(key in statement for key in ("NotAction", "NotResource", "NotPrincipal")):
                errors.append("Allow with NotAction/NotResource/NotPrincipal")
                continue
            actions = strings(statement.get("Action"))
            # AWS's canonical account-root delegation in a KMS key policy. Resource
            # '*' means THIS key, not all account keys. No identity policy exception.
            root_delegation = (
                kms_account is not None
                and actions == ["kms:*"]
                and strings(statement.get("Resource")) == ["*"]
                and statement.get("Principal") == {"AWS": f"arn:aws:iam::{kms_account}:root"}
                and not statement.get("Condition")
            )
            if root_delegation:
                continue
            if wildcard(actions):
                errors.append("wildcard Allow Action")
            if "Principal" in statement:
                principal = statement["Principal"]
                if not isinstance(principal, dict) or not principal:
                    errors.append("invalid or public Principal")
                else:
                    for value in principal.values():
                        strings(value)
                    if wildcard(principal):
                        errors.append("wildcard Allow Principal")
            elif trust:
                errors.append("trust policy has no Principal")
            if not trust:
                scope = strings(statement.get("Resource"))
                if wildcard(scope) and not (kms_account is not None and scope == ["*"]):
                    errors.append("wildcard Allow Resource")
    except (ValueError, TypeError, KeyError):
        errors.append("missing, unknown or malformed policy")
    return errors


def evaluate(plan: Plan, phase: Literal["changes", "resolved"] = "resolved") -> list[str]:
    try:
        return _evaluate(plan, phase)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return ["Invalid Terraform plan schema (fail closed)"]


def _evaluate(plan: Plan, phase: Literal["changes", "resolved"]) -> list[str]:
    """changes is ONLY for the isolated emulator's pre-apply deletion gate."""
    errors = []
    if not isinstance(plan.get("format_version"), str) or not plan["format_version"].startswith(
        "1."
    ):
        return ["unsupported/missing Terraform plan format_version"]
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"):
        errors.append("errored, incomplete or deferred plan")
    if "planned_values" not in plan or not isinstance(plan["planned_values"], dict):
        return [*errors, "missing planned_values"]
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        return [*errors, "invalid resource_changes"]
    for resource in changes:
        if resource.get("mode", "managed") != "managed":
            continue
        address = resource.get("address", "<unknown>")
        actions = resource.get("change", {}).get("actions", [])
        if tuple(actions) not in VALID_ACTIONS:
            errors.append(f"{address}: missing/unsupported actions")
        if "delete" in actions or "forget" in actions:
            errors.append(f"{address}: destroy/replacement/state removal is prohibited")
    if phase == "changes":
        return errors
    inventory = list(resources(plan["planned_values"].get("root_module", {})))
    # Include after values too, so a malformed empty snapshot cannot hide changes.
    by_address = {r["address"]: r for r in inventory}
    for resource in changes:
        if resource.get("mode", "managed") != "managed":
            continue
        change = resource.get("change", {})
        if change.get("after") is not None:
            by_address[resource["address"]] = {**resource, "values": change["after"]}
    policy_arns = {
        r.get("values", {}).get("arn") for r in by_address.values() if r["type"] == "aws_iam_policy"
    } - {None}
    encrypted_buckets = {
        r.get("values", {}).get("bucket")
        for r in by_address.values()
        if r["type"] == "aws_s3_bucket_server_side_encryption_configuration"
        and any(
            rule.get("apply_server_side_encryption_by_default", [{}])[0].get("sse_algorithm")
            in {"AES256", "aws:kms", "aws:kms:dsse"}
            for rule in r.get("values", {}).get("rule", [])
        )
    } - {None}
    for address, resource in by_address.items():
        kind = resource["type"]
        values = resource.get("values") or {}
        if kind not in SUPPORTED_TYPES:
            errors.append(f"{address}: unsupported resource type {kind}; add reviewed policies")
            continue
        if kind in POLICY_FIELDS:
            account = None
            if kind == "aws_kms_key":
                match = re.fullmatch(r"arn:aws:kms:[^:]+:([0-9]{12}):key/.+", values.get("arn", ""))
                account = match[1] if match else None
                if values.get("enable_key_rotation") is not True:
                    errors.append(f"{address}: KMS rotation is disabled/unknown")
            for issue in policy_errors(
                values.get(POLICY_FIELDS[kind]), trust=kind == "aws_iam_role", kms_account=account
            ):
                errors.append(f"{address}: {issue}")
            for inline in values.get("inline_policy") or []:
                for issue in policy_errors(inline.get("policy")):
                    errors.append(f"{address}: inline {issue}")
        field = ENCRYPTION_FIELDS.get(kind)
        if field:
            encrypted = values.get(field)
            if (field in {"encrypted", "storage_encrypted"} and encrypted is not True) or (
                field not in {"encrypted", "storage_encrypted"}
                and (not isinstance(encrypted, str) or not encrypted.strip() or wildcard(encrypted))
            ):
                errors.append(f"{address}: encryption is disabled/missing/unknown")
        if kind == "aws_secretsmanager_secret" and not re.fullmatch(
            r"arn:[^:]+:kms:[^:]+:[0-9]{12}:key/[^*?]+", str(values.get("kms_key_id", ""))
        ):
            errors.append(f"{address}: Secret must use an explicit customer-managed KMS key")
        if kind == "aws_sqs_queue" and not (
            values.get("sqs_managed_sse_enabled") is True
            or (
                isinstance(values.get("kms_master_key_id"), str)
                and values["kms_master_key_id"].strip()
                and not wildcard(values["kms_master_key_id"])
            )
        ):
            errors.append(f"{address}: SQS encryption is disabled/missing/unknown")
        if kind == "aws_s3_bucket" and values.get("id") not in encrypted_buckets:
            errors.append(f"{address}: missing S3 encryption configuration")
        if kind == "aws_dynamodb_table" and not any(
            sse.get("enabled") is True for sse in values.get("server_side_encryption", [])
        ):
            errors.append(f"{address}: DynamoDB encryption is disabled/missing/unknown")
        if kind.endswith("_policy_attachment") and values.get("policy_arn") not in policy_arns:
            errors.append(f"{address}: attached policy is external or unverified")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--phase", choices=("changes", "resolved"), default="resolved")
    args = parser.parse_args()
    try:
        issues = evaluate(json.loads(args.plan.read_text(encoding="utf-8")), args.phase)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        issues = ["Invalid Terraform plan JSON (fail closed)"]
    for issue in issues:
        print(issue)
    print(f"Plan policy: {'FAIL' if issues else 'PASS'} ({len(issues)} violations)")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
