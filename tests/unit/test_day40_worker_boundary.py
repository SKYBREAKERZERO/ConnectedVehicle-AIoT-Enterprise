"""Read-only Worker boundary admission must fail closed on real IAM/config drift."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest

from scripts.day40_worker_boundary import (
    MANAGED_EXEC,
    documents,
    inspect,
    role_policies,
    validate_trust,
)
from tests.unit.test_day39_worker_verify import reader as day39_reader

ACCOUNT = "123456789012"
TENANT = "tenant_staging_01"
REGION = "ap-northeast-1"
DIGEST = "sha256:" + "a" * 64
KMS = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRETS = {
    "outbox": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:/connected-vehicle/staging/database/outbox-aabbcc",
    "remote_command": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:/connected-vehicle/staging/database/remote-command-aabbcc",
    "campaign": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:/connected-vehicle/staging/database/application-aabbcc",
}
REDIS_SECRET = (
    f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:"
    "/connected-vehicle/staging/redis/auth-aabbcc"
)
QUEUE = f"arn:aws:sqs:{REGION}:{ACCOUNT}:cv-ota-staging-command"
DB_CONDITION = {
    "StringEquals": {
        "kms:ViaService": f"secretsmanager.{REGION}.amazonaws.com",
        "kms:EncryptionContext:SecretARN": SECRETS["outbox"],
    }
}


def policy_statement(
    sid: str, actions: list[str], resource: str, condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stmt: dict[str, Any] = {
        "Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resource,
    }
    if condition:
        stmt["Condition"] = condition
    return stmt


def policy_document(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def fixture() -> dict[str, Any]:
    return {
        "sts": day39_reader("sts", "get-caller-identity"),
        "db_secret": {
            "ARN": SECRETS["outbox"],
            "Name": "/connected-vehicle/staging/database/outbox",
            "KmsKeyId": KMS,
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "LastRotatedDate": "2026-11-16T00:00:00Z",
            "VersionIdsToStages": {"1": ["AWSCURRENT"]},
        },
        "queue": {
            "Attributes": {
                "QueueArn": QUEUE,
                "SqsManagedSseEnabled": "true",
                "VisibilityTimeout": "120",
                "RedrivePolicy": (
                    '{"deadLetterTargetArn":"arn:aws:sqs:ap-northeast-1:'
                    '123456789012:cv-ota-staging-command-dlq","maxReceiveCount":5}'
                ),
            },
        },
        "service": {
            **day39_reader(
                "ecs", "describe-services", "--cluster", "cv-ota-staging",
                "--services", "cv-ota-staging-outbox",
            ),
        },
        "role_policy": policy_document([
            policy_statement(
                "ReadExactlyOneTenantDatabaseSecret",
                ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
                SECRETS["outbox"],
            ),
            policy_statement(
                "DecryptExactlyOneTenantDatabaseSecret",
                ["kms:Decrypt"], KMS, DB_CONDITION,
            ),
            policy_statement(
                "SendCommandEventsOnly", ["sqs:GetQueueUrl", "sqs:SendMessage"], QUEUE,
            ),
        ]),
    }


def fake_read(data: dict[str, Any]) -> Callable[..., dict[str, Any]]:
    def get(*args: str) -> dict[str, Any]:
        if args[:2] == ("iam", "get-role"):
            role_name = args[3]
            return {"Role": {
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{role_name}",
                "Path": "/",
                "AssumeRolePolicyDocument": policy_document([{
                    "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }]),
            }}
        if args[:2] == ("iam", "list-role-policies"):
            return {"PolicyNames": (
                [] if args[3].endswith("-exec") else ["minimum-staging-worker-access"]
            )}
        if args[:2] == ("iam", "list-attached-role-policies"):
            return {"AttachedPolicies": (
                [{"PolicyArn": MANAGED_EXEC}] if args[3].endswith("-exec") else []
            )}
        if args[:2] == ("iam", "get-role-policy"):
            return {"PolicyDocument": deepcopy(data["role_policy"])}
        if args[:2] == ("secretsmanager", "describe-secret"):
            return deepcopy(data["db_secret"])
        if args[:2] == ("sqs", "get-queue-url"):
            return {
                "QueueUrl": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/cv-ota-staging-command",
            }
        if args[:2] == ("sqs", "get-queue-attributes"):
            return deepcopy(data["queue"])
        if args[:2] == ("ec2", "describe-security-groups"):
            return {"SecurityGroups": [{
                "GroupId": "sg-0123456789abcdef0",
                "GroupName": "cv-ota-staging-outbox-abc",
                "VpcId": "vpc-0123456789abcdef0",
                "IpPermissions": [],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "UserIdGroupPairs": [],
                    },
                    {
                        "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                        "IpRanges": [],
                        "UserIdGroupPairs": [{"GroupId": "sg-11111111"}],
                    },
                ],
            }]}
        if args[:2] == ("ecs", "describe-services"):
            result = deepcopy(data["service"])
            result["services"][0]["networkConfiguration"] = {
                "awsvpcConfiguration": {
                    "assignPublicIp": "DISABLED",
                    "securityGroups": ["sg-0123456789abcdef0"],
                }
            }
            return result
        if args[:2] == ("ecs", "describe-task-definition"):
            result = day39_reader(*args)
            task = result["taskDefinition"]
            task.update({
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "512",
                "memory": "1024",
            })
            container = task["containerDefinitions"][0]
            container.update({
                "user": "10001:10001",
                "secrets": [],
                "environment": [
                    {"name": k, "value": v}
                    for k, v in {
                        "APP_ENV": "staging", "CLOUD_RUNTIME": "aws",
                        "AWS_REGION": REGION, "AWS_ENDPOINT_URL": "",
                        "AWS_EC2_METADATA_DISABLED": "true",
                        "DATABASE_TENANT_ID": TENANT,
                        "VEHICLE_COMMAND_QUEUE_NAME": "cv-ota-staging-command",
                        "REDIS_HOST": "redis.private", "REDIS_PORT": "6379",
                        "OUTBOX_DATABASE_SECRET_ID": SECRETS["outbox"],
                    }.items()
                ],
            })
            return result
        return day39_reader(*args)

    return get


def observe(read: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    return inspect(
        read, account=ACCOUNT, cluster="cv-ota-staging", tenant=TENANT, digest=DIGEST,
        counts={"outbox": 1, "remote_command": 0, "campaign": 0}, secrets=SECRETS,
        redis_secret=REDIS_SECRET, kms_arn=KMS, redis_host="redis.private",
        iot_endpoint="", firmware_bucket=None, trust_file="",
        vpc_id="vpc-0123456789abcdef0",
        database_sg="sg-11111111", redis_sg="sg-22222222",
    )


def test_worker_all_exact_policy_and_configuration_checks_pass() -> None:
    report = observe(fake_read(fixture()))
    assert report["decision"] == "WORKER_IAM_CONFIG_OBSERVED"
    assert report["release_authorized"] is False
    assert report["credential_value_verified"] is False
    assert report["ota_runtime_verified"] is False
    assert report["verified"]["outbox"]["task_role_arn"].endswith("-outbox")


@pytest.mark.parametrize("tamper", [
    "extra-action", "extra-resource", "wrong-tenant-db", "wrong-kms", "wrong-dlq",
    "wrong-secret", "secret-not-rotating", "no-current", "public-ip", "public-ingress",
    "public-egress", "foreign-vpc",
    "extra-inline-policy", "extra-managed-policy", "wrong-assume-role",
    "wrong-task-env", "extra-password-env", "wrong-user", "wrong-image",
])
def test_worker_identity_or_config_drift_fails_closed(tamper: str) -> None:
    data = fixture()
    if tamper == "extra-action":
        data["role_policy"]["Statement"][0]["Action"].append("secretsmanager:DeleteSecret")
    elif tamper == "extra-resource":
        data["role_policy"]["Statement"][0]["Resource"] = "*"
    elif tamper == "wrong-tenant-db":
        data["role_policy"]["Statement"][0]["Resource"] = SECRETS["campaign"]
    elif tamper == "wrong-kms":
        data["db_secret"]["KmsKeyId"] = "arn:aws:kms:ap-northeast-1:999999999999:key/other"
    elif tamper == "wrong-dlq":
        data["queue"]["Attributes"]["RedrivePolicy"] = (
            '{"deadLetterTargetArn":"arn:aws:sqs:ap-northeast-1:123456789012:bad","maxReceiveCount":5}'
        )
    elif tamper == "wrong-secret":
        data["db_secret"]["Name"] = "/connected-vehicle/staging/database/application"
    elif tamper == "secret-not-rotating":
        data["db_secret"]["RotationEnabled"] = False
    elif tamper == "no-current":
        data["db_secret"]["VersionIdsToStages"] = {"1": ["AWSPREVIOUS"]}

    base = fake_read(data)

    def modified(*args: str) -> dict[str, Any]:
        response = base(*args)
        if tamper == "public-ip" and args[:2] == ("ecs", "describe-services"):
            response["services"][0]["networkConfiguration"]["awsvpcConfiguration"][
                "assignPublicIp"
            ] = "ENABLED"
        elif tamper == "public-ingress" and args[:2] == ("ec2", "describe-security-groups"):
            response["SecurityGroups"][0]["IpPermissions"] = [{"IpProtocol": "-1"}]
        elif tamper == "public-egress" and args[:2] == ("ec2", "describe-security-groups"):
            response["SecurityGroups"][0]["IpPermissionsEgress"].append({
                "IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            })
        elif tamper == "foreign-vpc" and args[:2] == ("ec2", "describe-security-groups"):
            response["SecurityGroups"][0]["VpcId"] = "vpc-ffffffff"
        elif tamper == "extra-inline-policy" and args[:2] == ("iam", "list-role-policies"):
            response["PolicyNames"].append("AdminAccess")
        elif tamper == "extra-managed-policy" and args[:2] == ("iam", "list-attached-role-policies"):
            response["AttachedPolicies"].append({"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        elif tamper == "wrong-assume-role" and args[:2] == ("iam", "get-role"):
            response["Role"]["AssumeRolePolicyDocument"]["Statement"][0][
                "Principal"
            ] = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
        elif tamper == "wrong-task-env" and args[:2] == ("ecs", "describe-task-definition"):
            response["taskDefinition"]["containerDefinitions"][0]["environment"][0][
                "value"
            ] = "production"
        elif tamper == "extra-password-env" and args[:2] == ("ecs", "describe-task-definition"):
            response["taskDefinition"]["containerDefinitions"][0]["environment"].append(
                {"name": "POSTGRES_PASSWORD", "value": "plaintext"}
            )
        elif tamper == "wrong-user" and args[:2] == ("ecs", "describe-task-definition"):
            response["taskDefinition"]["containerDefinitions"][0]["user"] = "0:0"
        elif tamper == "wrong-image" and args[:2] == ("ecs", "describe-task-definition"):
            response["taskDefinition"]["containerDefinitions"][0]["image"] = "repo@sha256:" + "b" * 64
        return response

    with pytest.raises(ValueError, match="WORKER BLOCKED"):
        observe(modified)


def test_dangerous_trust_and_json_encoded_policy_are_handled_correctly() -> None:
    valid = policy_document([{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    }])
    validate_trust(valid)
    assert documents('{"Version":"2012-10-17"}')["Version"] == "2012-10-17"
    bad = deepcopy(valid)
    bad["Statement"][0]["Principal"] = {"AWS": "*"}
    with pytest.raises(ValueError, match="WORKER BLOCKED"):
        validate_trust(bad)
