"""Negative regressions for resolved OTA database credential grants."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scripts.iac.ota_database_policy import database_isolation_errors


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    inputs: dict[str, Any] = {"aws_region": "ap-northeast-1", "api_runtime_role_name": "api"}
    items: list[dict[str, Any]] = [
        {
            "address": "module.campaign_runtime.aws_iam_role.this",
            "type": "aws_iam_role",
            "values": {"name": "campaign"},
        }
    ]
    for owner, module, role in (
        ("application", "database_read_policy", "api"),
        ("campaign", "campaign_database_read_policy", "campaign"),
    ):
        secret = f"arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:{owner}-abcdef"
        key = f"arn:aws:kms:ap-northeast-1:000000000000:key/{owner}-key"
        arn = f"arn:aws:iam::000000000000:policy/{owner}-database-read"
        inputs[f"{owner}_database_secret_arn"] = secret
        inputs[f"{owner}_database_kms_key_arn"] = key
        items.extend(
            [
                {
                    "address": f"module.{module}.aws_iam_policy.this",
                    "type": "aws_iam_policy",
                    "values": {
                        "arn": arn,
                        "policy": json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "ReadTenantDatabaseSecret",
                                        "Effect": "Allow",
                                        "Action": [
                                            "secretsmanager:GetSecretValue",
                                            "secretsmanager:DescribeSecret",
                                        ],
                                        "Resource": secret,
                                    },
                                    {
                                        "Sid": "DecryptTenantDatabaseSecret",
                                        "Effect": "Allow",
                                        "Action": ["kms:Decrypt"],
                                        "Resource": key,
                                        "Condition": {
                                            "StringEquals": {
                                                "kms:ViaService": (
                                                    "secretsmanager.ap-northeast-1.amazonaws.com"
                                                ),
                                                "kms:EncryptionContext:SecretARN": secret,
                                            }
                                        },
                                    },
                                ],
                            }
                        ),
                    },
                },
                {
                    "address": f"aws_iam_role_policy_attachment.{owner}",
                    "type": "aws_iam_role_policy_attachment",
                    "values": {"role": role, "policy_arn": arn},
                },
            ]
        )
    return {"planned_values": {"root_module": {"resources": items}}}, inputs


def test_distinct_credentials_and_contexts_pass() -> None:
    plan, inputs = fixture()
    assert not database_isolation_errors(plan, inputs)


@pytest.mark.parametrize("owner", ("application", "campaign"))
@pytest.mark.parametrize("violation", ("secret", "key", "service", "context", "action", "extra"))
def test_broad_or_cross_credential_grants_fail(owner: str, violation: str) -> None:
    plan, inputs = fixture()
    items = plan["planned_values"]["root_module"]["resources"]
    values = items[1 if owner == "application" else 3]["values"]
    policy = json.loads(values["policy"])
    statements = policy["Statement"]
    other = "campaign" if owner == "application" else "application"
    if violation == "secret":
        statements[0]["Resource"] = inputs[f"{other}_database_secret_arn"]
    elif violation == "key":
        statements[1]["Resource"] = "*"
    elif violation == "service":
        del statements[1]["Condition"]["StringEquals"]["kms:ViaService"]
    elif violation == "context":
        statements[1]["Condition"]["StringEquals"]["kms:EncryptionContext:SecretARN"] = inputs[
            f"{other}_database_secret_arn"
        ]
    elif violation == "action":
        statements[0]["Action"].append("secretsmanager:PutSecretValue")
    else:
        statements.append({"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"})
    values["policy"] = json.dumps(policy)
    assert database_isolation_errors(plan, inputs)


@pytest.mark.parametrize("index", (2, 4))
def test_cross_role_attachment_fails(index: int) -> None:
    plan, inputs = fixture()
    items = plan["planned_values"]["root_module"]["resources"]
    items[index]["values"]["role"] = "campaign" if index == 2 else "api"
    assert database_isolation_errors(plan, inputs)


@pytest.mark.parametrize(
    "violation", ("shared_secret", "shared_role", "role_case", "missing", "malformed")
)
def test_invalid_evidence_fails_closed(violation: str) -> None:
    plan, inputs = fixture()
    if violation == "shared_secret":
        inputs["campaign_database_secret_arn"] = inputs["application_database_secret_arn"]
    elif violation == "shared_role":
        inputs["api_runtime_role_name"] = "campaign"
    elif violation == "role_case":
        inputs["api_runtime_role_name"] = "CAMPAIGN"
    elif violation == "missing":
        plan.clear()
    else:
        plan["planned_values"]["root_module"]["resources"][1]["values"]["policy"] = "invalid"
    assert database_isolation_errors(plan, inputs)
