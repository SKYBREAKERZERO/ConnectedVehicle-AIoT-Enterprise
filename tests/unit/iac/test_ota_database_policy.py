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
    for module, name, action, resource in (
        (
            "artifact_policy",
            "this",
            "s3:GetObjectVersion",
            "arn:aws:s3:::contract-firmware/firmware/body.bin",
        ),
        (
            "ota_authority",
            "read",
            "secretsmanager:GetSecretValue",
            "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:authority-abcdef",
        ),
    ):
        arn = f"arn:aws:iam::000000000000:policy/{module}"
        items.append(
            {
                "address": f"module.{module}.aws_iam_policy.{name}",
                "type": "aws_iam_policy",
                "values": {
                    "arn": arn,
                    "policy": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": [action], "Resource": resource}
                            ],
                        }
                    ),
                },
            }
        )
        for role in ("api", "campaign"):
            items.append(
                {
                    "address": f"aws_iam_role_policy_attachment.{module}_{role}",
                    "type": "aws_iam_role_policy_attachment",
                    "values": {"role": role, "policy_arn": arn},
                }
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


@pytest.mark.parametrize("owner", ("application", "campaign"))
@pytest.mark.parametrize("action", ("secretsmanager:GetSecretValue", "kms:Decrypt", "KMS:dEcRyPt"))
def test_shared_policy_cannot_bypass_database_boundary(owner: str, action: str) -> None:
    plan, inputs = fixture()
    values = plan["planned_values"]["root_module"]["resources"][5]["values"]
    policy = json.loads(values["policy"])
    field = "kms_key" if action.lower().startswith("kms:") else "secret"
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Action": action,
            "Resource": inputs[f"{owner}_database_{field}_arn"],
        }
    )
    values["policy"] = json.dumps(policy)
    assert database_isolation_errors(plan, inputs)


@pytest.mark.parametrize(
    "violation",
    (
        "extra_attachment",
        "missing_shared_attachment",
        "duplicate_address",
        "inline",
        "embedded_inline",
        "embedded_managed",
        "missing_version",
        "duplicate_json_key",
        "shared_policy_identity",
        "unknown_shared_policy",
    ),
)
def test_bypass_and_ambiguous_evidence_fail(violation: str) -> None:
    plan, inputs = fixture()
    items = plan["planned_values"]["root_module"]["resources"]
    if violation == "extra_attachment":
        items.append(
            {
                "address": "aws_iam_role_policy_attachment.extra",
                "type": "aws_iam_role_policy_attachment",
                "values": {"role": "api", "policy_arn": "arn:aws:iam::000000000000:policy/extra"},
            }
        )
    elif violation == "missing_shared_attachment":
        items.pop()
    elif violation == "duplicate_address":
        items.append(items[0])
    elif violation == "inline":
        items.append(
            {
                "address": "aws_iam_role_policy.extra",
                "type": "aws_iam_role_policy",
                "values": {"role": "CAMPAIGN", "policy": "{}"},
            }
        )
    elif violation == "embedded_inline":
        items[0]["values"]["inline_policy"] = [{"name": "extra", "policy": "{}"}]
    elif violation == "embedded_managed":
        items[0]["values"]["managed_policy_arns"] = [items[1]["values"]["arn"]]
    elif violation == "missing_version":
        document = json.loads(items[1]["values"]["policy"])
        del document["Version"]
        items[1]["values"]["policy"] = json.dumps(document)
    elif violation == "duplicate_json_key":
        document = items[1]["values"]["policy"]
        items[1]["values"]["policy"] = document.replace("{", '{"Version":"2008-10-17",', 1)
    elif violation == "shared_policy_identity":
        items[5]["values"]["arn"] = items[1]["values"]["arn"]
    else:
        items[5]["values"]["policy"] = None
    assert database_isolation_errors(plan, inputs)


@pytest.mark.parametrize("action", ("secretsmanager:*", "*"))
def test_wildcard_side_grant_fails(action: str) -> None:
    plan, inputs = fixture()
    values = plan["planned_values"]["root_module"]["resources"][5]["values"]
    policy = json.loads(values["policy"])
    policy["Statement"].append({"Effect": "Allow", "Action": action, "Resource": "*"})
    values["policy"] = json.dumps(policy)
    assert database_isolation_errors(plan, inputs)


def test_explicit_deny_does_not_grant_database_access() -> None:
    plan, inputs = fixture()
    values = plan["planned_values"]["root_module"]["resources"][5]["values"]
    policy = json.loads(values["policy"])
    policy["Statement"].append({"Effect": "Deny", "Action": "*", "Resource": "*"})
    values["policy"] = json.dumps(policy)
    assert not database_isolation_errors(plan, inputs)


def test_resource_type_cannot_impersonate_policy() -> None:
    plan, inputs = fixture()
    plan["planned_values"]["root_module"]["resources"][1]["type"] = "aws_s3_bucket"
    assert database_isolation_errors(plan, inputs)
