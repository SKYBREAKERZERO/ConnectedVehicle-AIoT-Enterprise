"""Worker admission must use actual ECS task-role/digest observations, not Plan mocks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from scripts.day39_worker_verify import inspect

ACCOUNT = "123456789012"
DIGEST = "sha256:" + "a" * 64
TENANT = "tenant_staging_01"


def reader(*args: str) -> dict[str, Any]:
    if args[:2] == ("sts", "get-caller-identity"):
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/cv-ota-staging-verify/ci",
        }
    if args[:2] == ("ecs", "describe-services"):
        return {
            "services": [
                {
                    "serviceName": "cv-ota-staging-outbox",
                    "status": "ACTIVE",
                    "desiredCount": 1,
                    "runningCount": 1,
                    "pendingCount": 0,
                    "taskDefinition": (
                        "arn:aws:ecs:ap-northeast-1:123456789012:"
                        "task-definition/outbox:3"
                    ),
                    "deployments": [{"status": "PRIMARY", "rolloutState": "COMPLETED"}],
                }
            ]
        }
    if args[:2] == ("ecs", "list-tasks"):
        return {"taskArns": ["arn:aws:ecs:ap-northeast-1:123456789012:task/task-1"]}
    if args[:2] == ("ecs", "describe-task-definition"):
        return {
            "taskDefinition": {
                "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/cv-ota-staging-outbox",
                "executionRoleArn": f"arn:aws:iam::{ACCOUNT}:role/cv-ota-staging-outbox-exec",
                "containerDefinitions": [
                    {
                        "name": "worker-outbox",
                        "image": "repo@" + DIGEST,
                        "command": ["python", "-m", "apps.outbox_worker.main"],
                        "readonlyRootFilesystem": True,
                        "stopTimeout": 120,
                        "environment": [
                            {"name": "DATABASE_TENANT_ID", "value": TENANT},
                            {"name": "CLOUD_RUNTIME", "value": "aws"},
                            {"name": "AWS_ENDPOINT_URL", "value": ""},
                        ],
                    }
                ],
            }
        }
    if args[:2] == ("ecs", "describe-tasks"):
        return {
            "tasks": [
                {
                    "lastStatus": "RUNNING",
                    "launchType": "FARGATE",
                    "taskDefinitionArn": (
                        "arn:aws:ecs:ap-northeast-1:123456789012:"
                        "task-definition/outbox:3"
                    ),
                    "containers": [{"lastStatus": "RUNNING", "imageDigest": DIGEST}],
                }
            ]
        }
    raise AssertionError(f"Unexpected read-only AWS call: {args}")


def observe(read: Callable[..., dict[str, Any]] = reader) -> dict[str, Any]:
    return inspect(
        read,
        account=ACCOUNT,
        cluster="cv-ota-staging",
        tenant=TENANT,
        digest=DIGEST,
        counts={"outbox": 1, "remote_command": 0, "campaign": 0},
    )


def test_worker_real_identity_verification_only_not_release() -> None:
    report = observe()
    assert report["decision"] == "WORKER_IDENTITY_VERIFIED"
    assert report["release_authorized"] is False
    assert report["verified"]["outbox"]["running_count"] == 1


@pytest.mark.parametrize("tamper", ["wrong-tenant", "wrong-digest", "wrong-role", "unhealthy"])
def test_worker_tampering_denied(tamper: str) -> None:
    def altered(*args: str) -> dict[str, Any]:
        result = reader(*args)
        if tamper == "wrong-tenant" and args[1] == "describe-task-definition":
            environment = result["taskDefinition"]["containerDefinitions"][0]["environment"]
            environment[0]["value"] = "victim"
        elif tamper == "wrong-digest" and args[1] == "describe-tasks":
            result["tasks"][0]["containers"][0]["imageDigest"] = "sha256:" + "b" * 64
        elif tamper == "wrong-role" and args[1] == "describe-task-definition":
            result["taskDefinition"]["taskRoleArn"] = "arn:aws:iam::123456789012:role/admin"
        elif tamper == "unhealthy" and args[1] == "describe-services":
            result["services"][0]["pendingCount"] = 1
        return result

    with pytest.raises(ValueError, match="DAY39 WORKER BLOCKED"):
        observe(altered)


def test_workers_disabled_are_not_falsely_accepted() -> None:
    report = inspect(
        reader,
        account=ACCOUNT,
        cluster="cv-ota-staging",
        tenant=TENANT,
        digest=DIGEST,
        counts={"outbox": 0, "remote_command": 0, "campaign": 0},
    )
    assert report["decision"] == "WORKERS_DISABLED"
    assert report["release_authorized"] is False
