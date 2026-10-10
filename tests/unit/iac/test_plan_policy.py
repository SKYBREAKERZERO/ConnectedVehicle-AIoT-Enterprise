from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.plan_policy import evaluate, policy_errors

ACCOUNT = "000000000000"
KEY = f"arn:aws:kms:ap-northeast-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"
QUEUE = f"arn:aws:sqs:ap-northeast-1:{ACCOUNT}:command"
SCOPED: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["sqs:SendMessage"],
            "Resource": QUEUE,
        }
    ],
}


def plan(
    kind: str = "aws_sqs_queue",
    values: dict[str, Any] | None = None,
    actions: list[str] | None = None,
) -> dict[str, Any]:
    values = values if values is not None else {"sqs_managed_sse_enabled": True}
    resource = {
        "address": f"module.nested.{kind}.this",
        "mode": "managed",
        "type": kind,
        "values": values,
    }
    return {
        "format_version": "1.2",
        "complete": True,
        "planned_values": {"root_module": {"child_modules": [{"resources": [resource]}]}},
        "resource_changes": [
            {
                **resource,
                "change": {"actions": actions or ["no-op"], "after": values, "after_unknown": {}},
            }
        ],
    }


@pytest.mark.parametrize(
    "actions", [["delete"], ["delete", "create"], ["create", "delete"], ["forget"]]
)
def test_destroy_replacement_and_state_removal_are_denied(actions: list[str]) -> None:
    # Even 0 creates -> N destroys fails (no positive create-count prerequisite).
    document = plan(actions=actions)
    assert any("destroy" in issue for issue in evaluate(document, "changes"))
    assert any("destroy" in issue for issue in evaluate(document))


@pytest.mark.parametrize(
    "field,value",
    [
        ("Action", "*"),
        ("Action", ["sqs:*"]),
        ("Action", "sqs:Send?essage"),
        ("Resource", "*"),
        ("Resource", [QUEUE + "*"]),
        ("Principal", "*"),
        ("Principal", {"AWS": "*"}),
        ("NotAction", "iam:DeleteRole"),
        ("NotResource", QUEUE),
        ("NotPrincipal", {"AWS": ACCOUNT}),
    ],
)
def test_all_iam_wildcard_allow_variants_fail(field: str, value: Any) -> None:
    policy = deepcopy(SCOPED)
    policy["Statement"][0][field] = value
    assert evaluate(plan("aws_iam_policy", {"policy": json.dumps(policy)}))


def test_conditions_never_excuse_wildcard_identity_access() -> None:
    policy = deepcopy(SCOPED)
    policy["Statement"][0].update(
        {"Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": "ap-northeast-1"}}}
    )
    assert policy_errors(policy)


def test_deny_wildcards_and_scoped_allow_are_permitted() -> None:
    policy = deepcopy(SCOPED)
    policy["Statement"].append({"Effect": "Deny", "Action": "*", "Resource": "*"})
    assert not policy_errors(policy)


@pytest.mark.parametrize(
    "policy",
    [
        None,
        "not-json",
        {},
        {"Statement": []},
        {"Statement": [{}]},
        {"Statement": [{"Effect": "Allow", "Action": []}]},
    ],
)
def test_missing_unknown_or_malformed_policy_fails_closed(policy: Any) -> None:
    assert evaluate(plan("aws_iam_policy", {"policy": policy}))


def test_only_canonical_kms_root_delegation_has_a_wildcard_exception() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kms:*",
                "Resource": "*",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            }
        ]
    }
    assert not evaluate(
        plan("aws_kms_key", {"arn": KEY, "policy": json.dumps(policy), "enable_key_rotation": True})
    )
    assert evaluate(plan("aws_iam_policy", {"policy": json.dumps(policy)}))
    policy["Statement"][0]["Principal"] = {"AWS": "arn:aws:iam::111111111111:root"}
    assert evaluate(
        plan("aws_kms_key", {"arn": KEY, "policy": json.dumps(policy), "enable_key_rotation": True})
    )


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"sqs_managed_sse_enabled": False},
        {"kms_master_key_id": None},
        {"kms_master_key_id": "*"},
    ],
)
def test_unencrypted_or_unknown_sqs_fails(values: dict[str, Any]) -> None:
    assert evaluate(plan(values=values))


@pytest.mark.parametrize("values", [{"sqs_managed_sse_enabled": True}, {"kms_master_key_id": KEY}])
def test_either_sqs_encryption_mode_passes(values: dict[str, Any]) -> None:
    assert not evaluate(plan(values=values))


@pytest.mark.parametrize(
    "kind,values",
    [
        ("aws_secretsmanager_secret", {}),
        ("aws_sns_topic", {"kms_master_key_id": ""}),
        ("aws_db_instance", {"storage_encrypted": False}),
        ("aws_rds_cluster", {}),
        ("aws_ebs_volume", {"encrypted": False}),
        ("aws_efs_file_system", {}),
        ("aws_dynamodb_table", {"server_side_encryption": [{"enabled": False}]}),
        ("aws_s3_bucket", {"id": "unencrypted"}),
    ],
)
def test_data_resources_require_encryption(kind: str, values: dict[str, Any]) -> None:
    assert evaluate(plan(kind, values))


def test_unchanged_resources_are_checked_too() -> None:
    document = plan(
        "aws_iam_policy",
        {
            "policy": json.dumps(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            )
        },
    )
    document["resource_changes"] = []
    assert evaluate(document)


def test_unknown_new_type_and_external_admin_policy_cannot_bypass_gate() -> None:
    assert evaluate(plan("aws_lambda_function", {}))
    assert evaluate(
        plan(
            "aws_iam_role_policy_attachment",
            {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        )
    )


@pytest.mark.parametrize(
    "patch",
    [
        {"format_version": "2.0"},
        {"complete": False},
        {"errored": True},
        {"deferred_changes": [{}]},
        {"planned_values": None},
    ],
)
def test_unusable_plan_fails_closed(patch: dict[str, Any]) -> None:
    document = plan()
    document.update(patch)
    assert evaluate(document)


def test_cli_has_nonzero_exit_for_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("not a plan with secret-value", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.iac.plan_policy", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "secret-value" not in result.stdout
