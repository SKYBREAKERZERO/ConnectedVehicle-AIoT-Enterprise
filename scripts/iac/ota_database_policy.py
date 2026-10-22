"""Verify exact API/Campaign credential grants in a resolved OTA Terraform plan."""

from __future__ import annotations

import json
from typing import Any

from scripts.iac.plan_policy import resources


def database_isolation_errors(plan: dict[str, Any], inputs: dict[str, Any]) -> list[str]:
    """Fail closed on missing policies, cross-role attachments or broad decrypt grants.

    This checks grants owned by this root, not effective permissions inherited from
    externally managed IAM policies or the PostgreSQL identity inside a secret.
    """
    try:
        inventory = list(resources(plan["planned_values"]["root_module"]))
        indexed = {item["address"]: item["values"] for item in inventory}
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
            statements = json.loads(policy["policy"])["Statement"]
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
            if statements != expected_statements:
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
    except (AttributeError, KeyError, TypeError, ValueError):
        return ["Missing or malformed resolved OTA database isolation evidence"]
    return []
