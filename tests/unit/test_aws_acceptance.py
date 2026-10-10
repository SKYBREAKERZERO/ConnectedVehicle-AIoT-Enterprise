from copy import deepcopy
from typing import Any

import pytest

from scripts.aws_acceptance import collect, evaluate


def valid_evidence() -> dict[str, Any]:
    names = ("api", "outbox", "remote-command")
    return {
        "account": "123456789012",
        "expected_account": "123456789012",
        "database": {
            "StorageEncrypted": True,
            "KmsKeyId": "key",
            "MultiAZ": True,
            "PubliclyAccessible": False,
            "DeletionProtection": True,
            "BackupRetentionPeriod": 7,
            "DBInstanceStatus": "available",
        },
        "cache": {
            "TransitEncryptionEnabled": True,
            "AtRestEncryptionEnabled": True,
            "AutomaticFailover": "enabled",
            "MultiAZ": "enabled",
            "Status": "available",
        },
        "services": {
            name: {
                "desiredCount": 2,
                "runningCount": 2,
                "deployments": [{"rolloutState": "COMPLETED"}],
                "networkConfiguration": {
                    "awsvpcConfiguration": {"assignPublicIp": "DISABLED", "subnets": ["a", "b"]}
                },
            }
            for name in names
        },
        "queue": {"SqsManagedSseEnabled": "true", "RedrivePolicy": '{"deadLetterTargetArn":"dlq"}'},
        "dlq": {"QueueArn": "dlq", "SqsManagedSseEnabled": "true"},
        "secrets": {name: {"ARN": name, "KmsKeyId": "key"} for name in names},
        "roles": {name: "role-" + name for name in names},
        "task_definitions": {
            name: {
                "taskRoleArn": "role-" + name,
                "containerDefinitions": [
                    {
                        "image": "image@sha256:" + "a" * 64,
                        "environment": [
                            {"name": "CLOUD_RUNTIME", "value": "aws"},
                            {
                                "name": {
                                    "api": "APPLICATION_DATABASE_SECRET_ID",
                                    "outbox": "OUTBOX_DATABASE_SECRET_ID",
                                    "remote-command": "REMOTE_COMMAND_DATABASE_SECRET_ID",
                                }[name],
                                "value": name,
                            },
                        ],
                    }
                ],
            }
            for name in names
        },
        "secret_access": {
            name: {target: "allowed" if target == name else "implicitDeny" for target in names}
            for name in names
        },
        "alarms": [{"StateValue": "OK"}],
    }


def test_acceptance_requires_complete_secure_evidence() -> None:
    assert evaluate(valid_evidence()) == []
    assert evaluate({})
    evidence = valid_evidence()
    evidence["secret_access"]["outbox"]["api"] = "allowed"
    assert any("invalid access" in error for error in evaluate(evidence))
    for field, bad in (
        ("StorageEncrypted", False),
        ("MultiAZ", False),
        ("PubliclyAccessible", True),
        ("BackupRetentionPeriod", 0),
    ):
        evidence = deepcopy(valid_evidence())
        evidence["database"][field] = bad
        assert evaluate(evidence)


def test_aws_acceptance_refuses_emulator_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    with pytest.raises(ValueError, match="endpoint overrides"):
        collect({})
