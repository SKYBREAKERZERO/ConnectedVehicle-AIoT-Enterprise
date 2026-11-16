"""Fail-closed AWS Staging Worker IaC and runtime surface contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.day37_gate import plan_check

ROOT = Path(__file__).resolve().parents[2] / "infra/terraform/environments/ota-staging"


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_workers_are_disabled_by_default_and_isolated_from_api() -> None:
    variables = source("variables.tf")
    base = source("worker_base.tf")
    service = source("worker_service.tf")
    iam = source("worker_iam.tf")
    assert 'variable "enable_workers"' in variables
    assert "default = false" in variables
    assert "var.enable_service && var.enable_workers" in base
    assert 'resource "aws_ecs_service" "worker"' in service
    assert 'resource "aws_ecs_task_definition" "worker"' in service
    assert "readonlyRootFilesystem = true" in service
    assert "stopTimeout            = 120" in service
    assert "assign_public_ip = false" in service
    assert "prevent_destroy = true" in service
    assert 'resource "aws_iam_role" "worker"' in iam
    assert 'resource "aws_iam_role" "worker_execution"' in iam
    assert 'actions   = ["iot:Publish"]' in iam
    assert 'actions   = ["sqs:GetQueueUrl", "sqs:SendMessage"]' in iam
    assert '"sqs:ChangeMessageVisibility"' in iam


def test_queue_is_encrypted_bounded_and_has_dlq() -> None:
    base = source("worker_base.tf")
    assert base.count("sqs_managed_sse_enabled") == 2
    assert "maxReceiveCount     = 5" in base
    assert "visibility_timeout_seconds = 120" in base
    assert 'resource "aws_sqs_queue" "worker_commands"' in base
    assert 'resource "aws_sqs_queue" "worker_dlq"' in base
    assert "0.0.0.0/0" not in base.split('resource "aws_security_group" "worker"')[1].split('resource "aws_vpc_security_group_ingress_rule"')[0]


def _plan(name: str, cmd: list[str], *, enabled: bool = True) -> dict[str, object]:
    image = "sha256:" + "f" * 64
    return {
        "variables": {
            "enable_service": {"value": True},
            "enable_workers": {"value": enabled},
            "image_digest": {"value": image},
        },
        "resource_changes": [{
            "address": 'aws_ecs_task_definition.worker["outbox"]',
            "type": "aws_ecs_task_definition",
            "change": {"actions": ["create"], "after": {
                "container_definitions": (
                    '[{"name":"' + name + '","image":"repo@' + image +
                    '","readonlyRootFilesystem":true,"stopTimeout":120,"command":' +
                    __import__("json").dumps(cmd) + "}]"
                )
            }},
        }],
    }


def test_exact_worker_image_and_command_allowed_in_deploy_plan() -> None:
    image = "sha256:" + "f" * 64
    x = _plan("worker-outbox", ["python", "-m", "apps.outbox_worker.main"])
    assert plan_check(x, expected_digest=image, phase="deploy")["phase"] == "deploy"


@pytest.mark.parametrize("name,command,enabled", [
    ("worker-outbox", ["sh", "-c", "exit 0"], True),
    ("worker-evil", ["python", "-m", "apps.outbox_worker.main"], True),
    ("worker-outbox", ["python", "-m", "apps.outbox_worker.main"], False),
])
def test_unknown_or_unapproved_worker_deploy_plan_fails(
    name: str, command: list[str], enabled: bool
) -> None:
    with pytest.raises(ValueError, match="Unexpected"):
        plan_check(
            _plan(name, command, enabled=enabled),
            expected_digest="sha256:" + "f" * 64,
            phase="deploy",
        )
