"""Read-only AWS deployment acceptance. Requires explicit account and resource identifiers."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Protocol, cast

import boto3
from botocore.config import Config

from enterprise_platform.cloud.client_factory import Boto3ClientCreator


class ReadClient(Protocol):
    def __getattr__(self, name: str) -> Any: ...


def evaluate(evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected = evidence.get("expected_account", "")
    if (
        not isinstance(expected, str)
        or not re.fullmatch(r"[0-9]{12}", expected)
        or expected == "000000000000"
        or evidence.get("account") != expected
    ):
        errors.append("AWS account does not match the explicit deployment target")
    db = evidence.get("database", {})
    for field, condition in {
        "StorageEncrypted": db.get("StorageEncrypted") is True,
        "KmsKeyId": bool(db.get("KmsKeyId")),
        "MultiAZ": db.get("MultiAZ") is True,
        "PubliclyAccessible": db.get("PubliclyAccessible") is False,
        "DeletionProtection": db.get("DeletionProtection") is True,
        "BackupRetentionPeriod": db.get("BackupRetentionPeriod", 0) >= 7,
        "status": db.get("DBInstanceStatus") == "available",
    }.items():
        if not condition:
            errors.append(f"database acceptance failed: {field}")
    cache = evidence.get("cache", {})
    if not (
        cache.get("TransitEncryptionEnabled")
        and cache.get("AtRestEncryptionEnabled")
        and cache.get("AutomaticFailover") == "enabled"
        and cache.get("MultiAZ") == "enabled"
        and cache.get("Status") == "available"
    ):
        errors.append("cache requires encryption, availability and Multi-AZ automatic failover")
    services = evidence.get("services", {})
    if set(services) != {"api", "outbox", "remote-command"}:
        errors.append("three independent ECS services are required")
    for name, service in services.items():
        if service.get("desiredCount", 0) < 2 or service.get("runningCount") != service.get(
            "desiredCount"
        ):
            errors.append(f"{name}: at least two healthy ECS tasks are required")
        deployments = service.get("deployments", [])
        if len(deployments) != 1 or deployments[0].get("rolloutState") != "COMPLETED":
            errors.append(f"{name}: ECS rollout is incomplete")
        network = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
        if network.get("assignPublicIp") != "DISABLED" or len(set(network.get("subnets", []))) < 2:
            errors.append(f"{name}: private tasks across two subnets are required")
    queue = evidence.get("queue", {})
    if not (queue.get("KmsMasterKeyId") or queue.get("SqsManagedSseEnabled") == "true"):
        errors.append("command queue encryption is missing")
    redrive = json.loads(queue.get("RedrivePolicy", "{}"))
    if redrive.get("deadLetterTargetArn") != evidence.get("dlq", {}).get("QueueArn"):
        errors.append("DLQ association is missing or incorrect")
    dlq = evidence.get("dlq", {})
    if not (dlq.get("KmsMasterKeyId") or dlq.get("SqsManagedSseEnabled") == "true"):
        errors.append("DLQ encryption is missing")
    secrets = evidence.get("secrets", {})
    if (
        set(secrets) != {"api", "outbox", "remote-command"}
        or len({item.get("ARN") for item in secrets.values()}) != 3
    ):
        errors.append("three independent runtime Secrets are required")
    if any(not item.get("KmsKeyId") for item in secrets.values()):
        errors.append("runtime Secrets require customer-managed encryption")
    roles = evidence.get("roles", {})
    definitions = evidence.get("task_definitions", {})
    if set(roles) != set(secrets) or len(set(roles.values())) != 3:
        errors.append("three distinct runtime task roles are required")
    if set(definitions) != set(secrets):
        errors.append("actual ECS task definition evidence is incomplete")
    secret_fields = {
        "api": "APPLICATION_DATABASE_SECRET_ID",
        "outbox": "OUTBOX_DATABASE_SECRET_ID",
        "remote-command": "REMOTE_COMMAND_DATABASE_SECRET_ID",
    }
    for runtime, definition in definitions.items():
        if not roles.get(runtime) or definition.get("taskRoleArn") != roles[runtime]:
            errors.append(f"{runtime}: service is not attached to the verified task role")
        containers = definition.get("containerDefinitions", [])
        if len(containers) != 1:
            errors.append(f"{runtime}: runtime container ownership is ambiguous")
            continue
        container = containers[0]
        if "@sha256:" not in container.get("image", ""):
            errors.append(f"{runtime}: immutable image digest is required")
        values = {item["name"]: item["value"] for item in container.get("environment", [])}
        secret = secrets.get(runtime, {})
        configured_secret = values.get(secret_fields.get(runtime, ""))
        if not configured_secret or configured_secret not in {
            secret.get("ARN"),
            secret.get("Name"),
        }:
            errors.append(f"{runtime}: database Secret injection does not match the IAM contract")
        if values.get("CLOUD_RUNTIME") != "aws":
            errors.append(f"{runtime}: AWS runtime configuration is missing")
        injected = set(values) | {item["name"] for item in container.get("secrets", [])}
        if any(name.startswith("MIGRATION_") for name in injected) or (
            "DATABASE_PASSWORD" in injected or "API_SERVICE_TOKEN" in injected
        ):
            errors.append(f"{runtime}: admin/database password or local service token was injected")
    decisions = evidence.get("secret_access", {})
    if set(decisions) != set(secrets):
        errors.append("runtime IAM access evidence is incomplete")
    for runtime in secrets:
        access = decisions.get(runtime, {})
        if set(access) != set(secrets):
            errors.append(f"{runtime}: all three Secret access decisions are required")
        for target in secrets:
            decision = access.get(target)
            if (target == runtime and decision != "allowed") or (
                target != runtime and decision not in {"implicitDeny", "explicitDeny"}
            ):
                errors.append(f"{runtime}: invalid access to {target} Secret")
    alarms = evidence.get("alarms", [])
    if not alarms or any(item.get("StateValue") != "OK" for item in alarms):
        errors.append("configured deployment alarms must exist and be healthy")
    return errors


def collect(target: dict[str, Any]) -> dict[str, Any]:
    if any(name.startswith("AWS_ENDPOINT_URL") for name in os.environ):
        raise ValueError("AWS acceptance forbids endpoint overrides and LocalStack evidence.")
    if (
        not re.fullmatch(r"[0-9]{12}", str(target.get("account", "")))
        or target["account"] == "000000000000"
    ):
        raise ValueError("An explicit real AWS account ID is required.")
    for key in ("services", "secrets", "roles"):
        if set(target.get(key, {})) != {"api", "outbox", "remote-command"}:
            raise ValueError(f"{key} requires exactly three runtime identities.")
        if len(set(target[key].values())) != 3:
            raise ValueError(f"{key} must identify distinct runtime resources.")
    config = Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1})

    creator = cast(Boto3ClientCreator, boto3.client)

    def client(service: str) -> ReadClient:
        return cast(ReadClient, creator(service, region_name=target["region"], config=config))

    evidence: dict[str, Any] = {
        "expected_account": target["account"],
        "account": client("sts").get_caller_identity()["Account"],
        "region": target["region"],
    }
    if evidence["account"] != target["account"]:
        raise ValueError("AWS account mismatch; no resource checks were attempted.")
    evidence["database"] = client("rds").describe_db_instances(
        DBInstanceIdentifier=target["database_id"]
    )["DBInstances"][0]
    evidence["cache"] = client("elasticache").describe_replication_groups(
        ReplicationGroupId=target["cache_id"]
    )["ReplicationGroups"][0]
    evidence["services"] = {}
    evidence["roles"] = target["roles"]
    evidence["task_definitions"] = {}
    for runtime, service in target["services"].items():
        result = client("ecs").describe_services(cluster=target["cluster"], services=[service])
        if result.get("failures") or len(result.get("services", [])) != 1:
            raise ValueError(f"ECS service was not found: {runtime}")
        evidence["services"][runtime] = result["services"][0]
        evidence["task_definitions"][runtime] = client("ecs").describe_task_definition(
            taskDefinition=result["services"][0]["taskDefinition"]
        )["taskDefinition"]
    for name in ("queue", "dlq"):
        evidence[name] = client("sqs").get_queue_attributes(
            QueueUrl=target[name + "_url"], AttributeNames=["All"]
        )["Attributes"]
    evidence["secrets"] = {
        runtime: client("secretsmanager").describe_secret(SecretId=secret)
        for runtime, secret in target["secrets"].items()
    }
    evidence["secret_access"] = {}
    for runtime, role in target["roles"].items():
        evidence["secret_access"][runtime] = {}
        for destination, secret in evidence["secrets"].items():
            result = client("iam").simulate_principal_policy(
                PolicySourceArn=role,
                ActionNames=["secretsmanager:GetSecretValue"],
                ResourceArns=[secret["ARN"]],
            )
            evidence["secret_access"][runtime][destination] = result["EvaluationResults"][0][
                "EvalDecision"
            ]
    alarms = client("cloudwatch").describe_alarms(AlarmNames=target["alarm_names"])["MetricAlarms"]
    if {item["AlarmName"] for item in alarms} != set(target["alarm_names"]):
        raise ValueError("Some required deployment alarms were not found.")
    evidence["alarms"] = alarms
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    target = json.loads(args.target.read_text(encoding="utf-8"))
    evidence = collect(target)
    problems = evaluate(evidence)
    # Sanitized outcome only. Raw infrastructure metadata stays in memory.
    report = {
        "account": target["account"],
        "region": target["region"],
        "status": "failed" if problems else "passed",
        "errors": problems,
        "checks": ["database", "cache", "ecs", "queue", "dlq", "secrets", "iam", "alarms"],
        "scope": "configuration-readiness",
        "fault_injection_proven": False,
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
