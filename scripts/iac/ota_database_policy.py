"""Verify exact API/Campaign credential grants in a resolved OTA Terraform plan."""

from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import Any

from scripts.iac.plan_policy import resources, strings


def _document(raw: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate IAM document key")
            result[key] = value
        return result

    document = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(document, dict) or document.get("Version") != "2012-10-17":
        raise ValueError("Missing or unsupported IAM document version")
    return document


def database_isolation_errors(plan: dict[str, Any], inputs: dict[str, Any]) -> list[str]:
    """Fail closed on missing policies, cross-role attachments or broad decrypt grants.

    This checks grants owned by this root, not effective permissions inherited from
    externally managed IAM policies or the PostgreSQL identity inside a secret.
    """
    try:
        inventory = list(resources(plan["planned_values"]["root_module"]))
        indexed = {item["address"]: item["values"] for item in inventory}
        if len(indexed) != len(inventory):
            return ["Duplicate resource addresses in resolved OTA evidence"]
        types = {item["address"]: item["type"] for item in inventory}
        for address, kind in (
            ("module.campaign_runtime.aws_iam_role.this", "aws_iam_role"),
            ("module.database_read_policy.aws_iam_policy.this", "aws_iam_policy"),
            ("module.campaign_database_read_policy.aws_iam_policy.this", "aws_iam_policy"),
            ("module.artifact_policy.aws_iam_policy.this", "aws_iam_policy"),
            ("module.ota_authority.aws_iam_policy.read", "aws_iam_policy"),
        ):
            if types.get(address) != kind:
                return ["Missing or mistyped OTA role/policy evidence"]
        campaign_role = indexed["module.campaign_runtime.aws_iam_role.this"]["name"]
        roles = [inputs["api_runtime_role_name"], campaign_role]
        secrets = [inputs[f"{owner}_database_secret_arn"] for owner in ("application", "campaign")]
        if len({role.lower() for role in roles}) != 2 or len(set(secrets)) != 2:
            return ["API/Campaign roles and database secrets must be distinct"]
        expected: set[tuple[str, str]] = set()
        database_arns = []
        for owner, module, role, secret in zip(
            ("application", "campaign"),
            ("database_read_policy", "campaign_database_read_policy"),
            roles,
            secrets,
            strict=True,
        ):
            policy = indexed[f"module.{module}.aws_iam_policy.this"]
            document = _document(policy["policy"])
            expected_statements = [
                {
                    "Sid": "ReadTenantDatabaseSecret",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                    "Resource": secret,
                },
                {
                    "Sid": "DecryptTenantDatabaseSecret",
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt"],
                    "Resource": inputs[f"{owner}_database_kms_key_arn"],
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": (
                                f"secretsmanager.{inputs['aws_region']}.amazonaws.com"
                            ),
                            "kms:EncryptionContext:SecretARN": secret,
                        }
                    },
                },
            ]
            if document != {"Version": "2012-10-17", "Statement": expected_statements}:
                return [f"{owner}: database policy differs from the exact credential boundary"]
            database_arns.append(policy["arn"])
            expected.add((role, policy["arn"]))
        if len(set(database_arns)) != 2:
            return ["Database read policies must be distinct"]
        actual = [
            (item["values"]["role"], item["values"]["policy_arn"])
            for item in inventory
            if item["type"] == "aws_iam_role_policy_attachment"
            and item["values"]["policy_arn"] in database_arns
        ]
        if len(actual) != 2 or set(actual) != expected:
            return ["Database policies must attach exclusively to their owning runtime roles"]
        shared_arns = {
            indexed[f"module.{module}.aws_iam_policy.{name}"]["arn"]
            for module, name in (("artifact_policy", "this"), ("ota_authority", "read"))
        }
        if len(shared_arns | set(database_arns)) != 4:
            return ["OTA runtime policy identities must be distinct"]
        expected |= {(role, arn) for role in roles for arn in shared_arns}
        protected_roles = {role.lower() for role in roles}
        attached = [
            (item["values"]["role"], item["values"]["policy_arn"])
            for item in inventory
            if item["type"] == "aws_iam_role_policy_attachment"
            and item["values"]["role"].lower() in protected_roles
        ]
        if len(attached) != 6 or set(attached) != expected:
            return ["Each OTA runtime must have only its three approved policy attachments"]
        keys = [inputs[f"{owner}_database_kms_key_arn"] for owner in ("application", "campaign")]
        for item in inventory:
            kind, values = item["type"], item["values"]
            if kind == "aws_iam_role_policy" and values["role"].lower() in protected_roles:
                return ["Inline runtime policies are outside the approved OTA permission matrix"]
            if kind == "aws_iam_role" and values["name"].lower() in protected_roles:
                if values.get("inline_policy"):
                    return ["Embedded inline runtime policies are prohibited"]
                approved = {arn for role, arn in expected if role.lower() == values["name"].lower()}
                if set(values.get("managed_policy_arns") or []) - approved:
                    return ["Embedded managed policies are outside the approved OTA matrix"]
            if kind != "aws_iam_policy" or values["arn"] in database_arns:
                continue
            statements = _document(values["policy"])["Statement"]
            statements = [statements] if isinstance(statements, dict) else statements
            if not isinstance(statements, list) or not statements:
                raise ValueError("Missing IAM statements")
            for statement in statements:
                if statement["Effect"] == "Deny":
                    continue
                if statement["Effect"] != "Allow" or any(
                    field in statement for field in ("NotAction", "NotResource", "NotPrincipal")
                ):
                    raise ValueError("Unsupported IAM grant")
                actions, targets = strings(statement["Action"]), strings(statement["Resource"])
                for action, protected in (
                    ("secretsmanager:GetSecretValue", secrets),
                    ("secretsmanager:DescribeSecret", secrets),
                    ("kms:Decrypt", keys),
                ):
                    if any(
                        fnmatchcase(action.lower(), pattern.lower()) for pattern in actions
                    ) and any(
                        fnmatchcase(target, pattern) for target in protected for pattern in targets
                    ):
                        return [
                            "A non-database policy grants access to protected database resources"
                        ]
    except (AttributeError, KeyError, TypeError, ValueError):
        return ["Missing or malformed resolved OTA database isolation evidence"]
    return []
