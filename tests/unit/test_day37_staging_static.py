"""Static safety contracts; never claim Terraform provider / AWS acceptance from these tests."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "infra/terraform/environments/ota-staging"


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_isolated_staging_root() -> None:
    assert "backend \"s3\"" in source("versions.tf")
    assert "use_lockfile = true" in source("versions.tf")
    assert re.search(r"allowed_account_ids\s*=\s*\[var\.aws_account_id\]", source("provider.tf"))
    assert 'Environment = "staging"' in source("provider.tf")


def test_plan_only_default_and_digest_strict() -> None:
    v = source("variables.tf")
    assert re.search(r'variable "enable_service"\s*\{[^{}]*default\s*=\s*false', v)
    assert re.search(r'variable "image_digest"\s*\{[^{}]*default\s*=\s*null', v)
    assert re.search(r'variable "desired_count"\s*\{[^{}]*default\s*=\s*0', v)
    assert "^sha256:[0-9a-f]{64}$" in v
    main = source("main.tf")
    assert 'count                    = var.enable_service ? 1 : 0' in main
    assert 'count           = var.enable_service ? 1 : 0' in main
    assert 'data.aws_ecr_image.candidate[0].image_uri' in main
    assert 'data "aws_ecr_image" "candidate"' in main
    assert "${var.image_digest}" not in main.split('container_definitions = jsonencode(', 1)[1]


def test_ecr_immutable_non_deletable() -> None:
    main = source("main.tf")
    assert 'image_tag_mutability = "IMMUTABLE"' in main
    assert 'force_delete         = false' in main
    assert main.count('prevent_destroy = true') >= 3


def test_service_private_and_failure_rollback() -> None:
    main = source("main.tf")
    for snippet in (
        'assign_public_ip = false',
        'enable_execute_command = false',
        'deployment_circuit_breaker',
        'rollback = true',
        'wait_for_steady_state = true',
        'data.aws_lb_target_group.existing[0].target_type == "ip"',
        'readonlyRootFilesystem = true',
        'user              = "10001:10001"',
        '"/health/ready"',
    ):
        if snippet == '"/health/ready"':
            assert "/health/ready" in main
        else:
            assert re.sub(r"[ \t]+", " ", snippet) in re.sub(r"[ \t]+", " ", main)


def test_separated_runtime_and_execution_identity() -> None:
    iam = source("iam.tf")
    main = source("main.tf")
    assert 'resource "aws_iam_role" "execution"' in iam
    assert 'resource "aws_iam_role" "application"' in iam
    assert '"secretsmanager:GetSecretValue"' in iam
    assert 'resources = [var.application_database_secret_arn]' in iam
    assert 'task_role_arn            = aws_iam_role.application.arn' in main
    assert 'execution_role_arn       = aws_iam_role.execution.arn' in main
    assert 'MIGRATION_DATABASE_PASSWORD' not in main
    assert 'BOOTSTRAP_DATABASE_PASSWORD' not in main
    assert '"APP_ENV", value = "staging"' in main
    assert '"CLOUD_RUNTIME", value = "aws"' in main


def test_no_aws_actions_or_unsafe_auto_apply() -> None:
    all_text = "\n".join(p.read_text() for p in ROOT.glob("*.tf"))
    assert 'resource "aws_db_instance"' not in all_text
    assert 'resource "aws_lb"' not in all_text
    assert 'resource "aws_iam_openid_connect_provider"' not in all_text
    assert 'data "aws_ecr_image"' in all_text
    assert not list(ROOT.glob("*.tfplan"))
    assert 'value       = false' in source("outputs.tf")


@pytest.mark.parametrize("name", [
    "versions.tf", "provider.tf", "variables.tf", "main.tf", "iam.tf", "outputs.tf"
])
def test_balanced_hcl_braces_outside_comments_and_strings(name: str) -> None:
    # Very small structural check. Terraform fmt/validate must still be executed
    # by a real Terraform binary and AWS provider before accepting this module.
    text = source(name)
    count = 0
    in_string = False
    esc = False
    for line in text.splitlines():
        for char in line:
            if not in_string and char == '#':
                break
            if in_string:
                if esc:
                    esc = False
                elif char == '\\':
                    esc = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == '{':
                count += 1
            elif char == '}':
                count -= 1
                assert count >= 0, name
    assert count == 0 and not in_string, name
