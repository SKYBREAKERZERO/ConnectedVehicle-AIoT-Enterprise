"""Independent, read-only AWS Staging Worker IAM, Secret and configuration audit.

Does not read Secret values, execute workers, deploy resources or authorize OTA.
Source-of-truth expectations come from an independently approved deploy config,
not self-reported Task Definition environment values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

from scripts.day39_worker_verify import KINDS, aws, inspect as inspect_tasks

REGION = "ap-northeast-1"
ROLE_PREFIX = "cv-ota-staging"
MANAGED_EXEC = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
DB_NAMES = {
    "outbox": "/connected-vehicle/staging/database/outbox",
    "remote_command": "/connected-vehicle/staging/database/remote-command",
    "campaign": "/connected-vehicle/staging/database/application",
}
Reader = Callable[..., dict[str, Any]]


def require(ok: Any, message: str) -> None:
    if not ok:
        raise ValueError("DAY40 WORKER BLOCKED: " + message)


def documents(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except ValueError as exc:
            raise ValueError("DAY40 WORKER BLOCKED: invalid IAM policy document") from exc
    require(isinstance(value, dict), "IAM policy is not a document")
    return cast(dict[str, Any], value)


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def only_statements(policy: Any) -> dict[str, dict[str, Any]]:
    doc = documents(policy)
    require(doc.get("Version") == "2012-10-17", "wrong IAM policy language")
    entries = as_list(doc.get("Statement", []))
    require(bool(entries) and all(isinstance(s, dict) for s in entries), "invalid IAM statements")
    result: dict[str, dict[str, Any]] = {}
    for stmt in entries:
        sid = stmt.get("Sid")
        require(isinstance(sid, str) and sid and sid not in result, "duplicate/missing IAM Sid")
        require(
            stmt.get("Effect") == "Allow"
            and not any(k in stmt for k in ("NotAction", "NotResource", "Principal", "NotPrincipal")),
            "unexpected IAM privilege semantics",
        )
        result[sid] = stmt
    return result


def exact_statement(
    stmt: Mapping[str, Any],
    *,
    actions: set[str],
    resources: set[str],
    condition: dict[str, Any] | None = None,
) -> None:
    require(set(as_list(stmt.get("Action"))) == actions, "IAM action drift")
    require(set(as_list(stmt.get("Resource"))) == resources, "IAM resource drift")
    require(stmt.get("Condition") == condition if condition else "Condition" not in stmt, "IAM condition drift")


def kms_condition(account: str, secret_arn: str) -> dict[str, Any]:
    return {"StringEquals": {
        "kms:ViaService": f"secretsmanager.{REGION}.amazonaws.com",
        "kms:EncryptionContext:SecretARN": secret_arn,
    }}


def validate_trust(data: Any) -> None:
    doc = documents(data)
    require(doc.get("Version") == "2012-10-17", "IAM trust version mismatch")
    statements = as_list(doc.get("Statement", []))
    require(len(statements) == 1 and isinstance(statements[0], dict), "IAM trust has extra statements")
    stmt = statements[0]
    require(
        stmt.get("Effect") == "Allow"
        and set(as_list(stmt.get("Action"))) == {"sts:AssumeRole"}
        and stmt.get("Principal") == {"Service": "ecs-tasks.amazonaws.com"}
        and "Condition" not in stmt
        and not any(k in stmt for k in ("NotAction", "NotPrincipal", "NotResource")),
        "IAM role is not ECS-tasks-only",
    )


def role_policies(
    read: Reader, account: str, kind: str, *, execution: bool, db_secret: str,
    redis_secret: str, kms_arn: str, queue_arn: str, tenant: str,
    firmware_bucket: str | None,
) -> str:
    suffix = kind.replace("_", "-")
    role_name = f"{ROLE_PREFIX}-{suffix}" + ("-exec" if execution else "")
    arn = f"arn:aws:iam::{account}:role/{role_name}"
    role = read("iam", "get-role", "--role-name", role_name).get("Role", {})
    require(role.get("Arn") == arn and role.get("Path") == "/", "Worker IAM role identity drift")
    validate_trust(role.get("AssumeRolePolicyDocument"))
    inline = read("iam", "list-role-policies", "--role-name", role_name)
    attached = read("iam", "list-attached-role-policies", "--role-name", role_name)
    require(not inline.get("IsTruncated") and not attached.get("IsTruncated"), "truncated IAM inventory")
    inline_names = inline.get("PolicyNames", [])
    attached_arns = [x.get("PolicyArn") for x in attached.get("AttachedPolicies", [])]
    require(
        inline_names == (["inject-redis-token-only"] if execution and kind == "remote_command"
                         else [] if execution else ["minimum-staging-worker-access"]),
        "Worker inline policy inventory changed",
    )
    require(
        sorted(attached_arns) == ([MANAGED_EXEC] if execution else []),
        "unexpected Worker managed IAM policy",
    )
    if execution and kind != "remote_command":
        return arn
    policy_name = "inject-redis-token-only" if execution else "minimum-staging-worker-access"
    policy = read(
        "iam", "get-role-policy", "--role-name", role_name, "--policy-name", policy_name,
    ).get("PolicyDocument")
    entries = only_statements(policy)
    if execution:
        require(
            set(entries) == {"InjectRemoteRedisOnly", "DecryptRemoteRedisOnly"},
            "Worker Redis execution privilege drift",
        )
        exact_statement(
            entries["InjectRemoteRedisOnly"], actions={"secretsmanager:GetSecretValue"},
            resources={redis_secret},
        )
        exact_statement(
            entries["DecryptRemoteRedisOnly"], actions={"kms:Decrypt"},
            resources={kms_arn}, condition=kms_condition(account, redis_secret),
        )
        return arn

    expected = {"ReadExactlyOneTenantDatabaseSecret", "DecryptExactlyOneTenantDatabaseSecret"}
    if kind == "outbox":
        expected.add("SendCommandEventsOnly")
    if kind == "remote_command":
        expected.update({"ConsumeCommandEventsOnly", "PublishOnlyTenantDeviceCommands"})
    if kind == "campaign" and firmware_bucket:
        expected.add("ReadPinnedStagingFirmwareVersionOnly")
    require(set(entries) == expected, "unexpected Worker task policy statements")
    exact_statement(
        entries["ReadExactlyOneTenantDatabaseSecret"],
        actions={"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"},
        resources={db_secret},
    )
    exact_statement(
        entries["DecryptExactlyOneTenantDatabaseSecret"],
        actions={"kms:Decrypt"}, resources={kms_arn},
        condition=kms_condition(account, db_secret),
    )
    if kind == "outbox":
        exact_statement(
            entries["SendCommandEventsOnly"], actions={"sqs:GetQueueUrl", "sqs:SendMessage"},
            resources={queue_arn},
        )
    if kind == "remote_command":
        exact_statement(
            entries["ConsumeCommandEventsOnly"],
            actions={"sqs:GetQueueUrl", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                     "sqs:ChangeMessageVisibility"},
            resources={queue_arn},
        )
        exact_statement(
            entries["PublishOnlyTenantDeviceCommands"], actions={"iot:Publish"},
            resources={
                f"arn:aws:iot:{REGION}:{account}:topic/tenants/{tenant}/vehicles/*/commands"
            },
        )
    if kind == "campaign" and firmware_bucket:
        exact_statement(
            entries["ReadPinnedStagingFirmwareVersionOnly"], actions={"s3:GetObjectVersion"},
            resources={f"{firmware_bucket}/firmware/{tenant}/*"},
        )
    return arn


def verify_secret(read: Reader, account: str, name: str, arn: str, kms: str) -> None:
    require(
        re.fullmatch(
            rf"arn:aws:secretsmanager:{REGION}:{account}:secret:{re.escape(name)}-[A-Za-z0-9]{{6}}",
            arn,
        ),
        "Secret does not match exact staging account and name",
    )
    data = read("secretsmanager", "describe-secret", "--secret-id", arn)
    require(
        data.get("ARN") == arn and data.get("Name") == name and data.get("KmsKeyId") == kms
        and not data.get("DeletedDate") and data.get("RotationEnabled") is True
        and bool(data.get("RotationRules")) and bool(data.get("LastRotatedDate")),
        "database/Redis Secret is missing, unrotated, deleted or uses incorrect KMS",
    )
    stages = data.get("VersionIdsToStages", {})
    require(
        isinstance(stages, dict)
        and all(isinstance(v, list) for v in stages.values())
        and sum("AWSCURRENT" in v for v in stages.values()) == 1,
        "Secret AWSCURRENT must be unique",
    )


def check_queue(read: Reader, account: str) -> str:
    name = f"{ROLE_PREFIX}-command"
    arn = f"arn:aws:sqs:{REGION}:{account}:{name}"
    queue_url = read("sqs", "get-queue-url", "--queue-name", name).get("QueueUrl")
    require(
        isinstance(queue_url, str)
        and queue_url.startswith(f"https://sqs.{REGION}.amazonaws.com/{account}/{name}"),
        "SQS URL/account mismatch",
    )
    attr = read(
        "sqs", "get-queue-attributes", "--queue-url", queue_url, "--attribute-names", "All",
    ).get("Attributes", {})
    require(
        attr.get("QueueArn") == arn
        and attr.get("SqsManagedSseEnabled") == "true"
        and attr.get("VisibilityTimeout") == "120",
        "SQS ARN, encryption or visibility is unapproved",
    )
    try:
        redrive = json.loads(attr.get("RedrivePolicy", ""))
    except ValueError as exc:
        raise ValueError("DAY40 WORKER BLOCKED: invalid SQS DLQ policy") from exc
    require(
        redrive == {
            "deadLetterTargetArn": f"arn:aws:sqs:{REGION}:{account}:{ROLE_PREFIX}-command-dlq",
            "maxReceiveCount": 5,
        } or redrive == {
            "deadLetterTargetArn": f"arn:aws:sqs:{REGION}:{account}:{ROLE_PREFIX}-command-dlq",
            "maxReceiveCount": "5",
        },
        "SQS DLQ and retry policy differ from reviewed configuration",
    )
    return arn


def verify_task(
    read: Reader, kind: str, *,
    account: str, tenant: str, digest: str, cluster: str,
    db_secret: str, redis_secret: str, kms: str, queue_arn: str,
    redis_host: str, iot_endpoint: str, firmware_bucket: str | None,
    trust_file: str, vpc_id: str, database_sg: str, redis_sg: str,
) -> dict[str, str]:
    name = f"{ROLE_PREFIX}-{kind.replace('_', '-')}"
    task_role = role_policies(
        read, account, kind, execution=False, db_secret=db_secret,
        redis_secret=redis_secret, kms_arn=kms, queue_arn=queue_arn,
        tenant=tenant, firmware_bucket=firmware_bucket,
    )
    exec_role = role_policies(
        read, account, kind, execution=True, db_secret=db_secret,
        redis_secret=redis_secret, kms_arn=kms, queue_arn=queue_arn,
        tenant=tenant, firmware_bucket=firmware_bucket,
    )
    service = read("ecs", "describe-services", "--cluster", cluster, "--services", name)
    rows = service.get("services", [])
    require(len(rows) == 1 and not service.get("failures"), "missing Worker ECS service")
    svc = rows[0]
    network = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
    sgs = network.get("securityGroups", [])
    require(
        network.get("assignPublicIp") == "DISABLED" and len(sgs) == 1,
        "Worker must use one private Security Group without a public IP",
    )
    sg_data = read("ec2", "describe-security-groups", "--group-ids", sgs[0])
    groups = sg_data.get("SecurityGroups", [])
    require(
        len(groups) == 1 and groups[0].get("GroupId") == sgs[0]
        and groups[0].get("GroupName", "").startswith(name + "-")
        and groups[0].get("VpcId") == vpc_id
        and groups[0].get("IpPermissions") == [],
        "Worker Security Group identity or ingress drift",
    )
    egress = groups[0].get("IpPermissionsEgress", [])
    require(isinstance(egress, list), "Worker egress inventory malformed")
    def destination(item: dict[str, Any]) -> tuple[int, str] | None:
        if (
            item.get("IpProtocol") != "tcp"
            or item.get("FromPort") != item.get("ToPort")
        ):
            return None
        port = item.get("FromPort")
        targets = item.get("IpRanges", [])
        peers = item.get("UserIdGroupPairs", [])
        if port == 443 and len(targets) == 1 and not peers:
            return (443, "public-https") if targets[0].get("CidrIp") == "0.0.0.0/0" else None
        if len(peers) == 1 and not targets:
            return (port, peers[0].get("GroupId"))
        return None

    expected_egress = {(443, "public-https"), (5432, database_sg)}
    if kind == "remote_command":
        expected_egress.add((6379, redis_sg))
    require(
        len(egress) == len(expected_egress)
        and {destination(entry) for entry in egress} == expected_egress,
        "Worker Security Group egress has unauthorized destinations",
    )
    definition_arn = svc.get("taskDefinition")
    task = read(
        "ecs", "describe-task-definition", "--task-definition", definition_arn,
    ).get("taskDefinition", {})
    containers = task.get("containerDefinitions", [])
    require(
        len(containers) == 1 and task.get("taskRoleArn") == task_role
        and task.get("executionRoleArn") == exec_role
        and task.get("networkMode") == "awsvpc"
        and "FARGATE" in task.get("requiresCompatibilities", [])
        and str(task.get("cpu")) == "512" and str(task.get("memory")) == "1024",
        "Worker Task Role, Execution Role or Fargate configuration drift",
    )
    container = containers[0]
    require(
        container.get("name") == f"worker-{kind.replace('_', '-')}"
        and container.get("image", "").endswith("@" + digest)
        and container.get("command") == KINDS[kind]
        and container.get("readonlyRootFilesystem") is True
        and container.get("user") == "10001:10001"
        and container.get("stopTimeout") == 120,
        "Worker executable/image/user/rootfs drift",
    )
    env_list = container.get("environment", [])
    require(isinstance(env_list, list) and all(isinstance(e, dict) for e in env_list),
            "malformed ECS environment")
    environment = {entry.get("name"): entry.get("value") for entry in env_list}
    require(len(environment) == len(env_list), "duplicate Worker environment key")
    expected = {
        "APP_ENV": "staging", "CLOUD_RUNTIME": "aws", "AWS_REGION": REGION,
        "AWS_ENDPOINT_URL": "", "AWS_EC2_METADATA_DISABLED": "true",
        "DATABASE_TENANT_ID": tenant,
        "VEHICLE_COMMAND_QUEUE_NAME": f"{ROLE_PREFIX}-command",
        "REDIS_HOST": redis_host, "REDIS_PORT": "6379",
    }
    if kind == "outbox":
        expected["OUTBOX_DATABASE_SECRET_ID"] = db_secret
    elif kind == "remote_command":
        expected["REMOTE_COMMAND_DATABASE_SECRET_ID"] = db_secret
        expected["AWS_IOT_DATA_ENDPOINT"] = iot_endpoint
    else:
        expected["APPLICATION_DATABASE_SECRET_ID"] = db_secret
        expected["OTA_TRUSTED_KEYS_FILE"] = trust_file
    require(environment == expected, "Worker tenant, Secret, IoT or environment drift")
    secret_refs = container.get("secrets", [])
    require(
        secret_refs == (
            [{"name": "REDIS_PASSWORD", "valueFrom": redis_secret}]
            if kind == "remote_command" else []
        ),
        "Worker contains unauthorized injected Secrets",
    )
    return {"task_role_arn": task_role, "execution_role_arn": exec_role,
            "service": name, "security_group_id": sgs[0], "task_definition": definition_arn}


def inspect(
    read: Reader, *, account: str, cluster: str, tenant: str, digest: str,
    counts: dict[str, int], secrets: dict[str, str], redis_secret: str,
    kms_arn: str, redis_host: str, iot_endpoint: str, firmware_bucket: str | None,
    trust_file: str, vpc_id: str, database_sg: str, redis_sg: str,
) -> dict[str, Any]:
    require(
        bool(re.fullmatch(r"[0-9]{12}", account)) and cluster == ROLE_PREFIX
        and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tenant)),
        "foreign account/cluster/tenant",
    )
    require(bool(re.fullmatch(r"sha256:[a-f0-9]{64}", digest)), "invalid digest")
    require(set(secrets) == set(KINDS), "missing Worker database Secret mapping")
    require(
        all(isinstance(x, str) for x in secrets.values())
        and len(set(secrets.values())) == 3
        and bool(re.fullmatch(r"arn:aws:kms:ap-northeast-1:[0-9]{12}:key/[A-Za-z0-9-]+", kms_arn))
        and kms_arn.split(":")[4] == account,
        "invalid KMS or per-Worker Secret isolation",
    )
    require(bool(redis_host) and not redis_host.startswith("http"), "invalid Redis host")
    require(
        all(re.fullmatch(r"sg-[a-f0-9]{8,17}", value)
            for value in (database_sg, redis_sg))
        and bool(re.fullmatch(r"vpc-[a-f0-9]{8,17}", vpc_id)),
        "invalid approved VPC/database/Redis Security Group",
    )
    identity = inspect_tasks(read, account=account, cluster=cluster, tenant=tenant,
                             digest=digest, counts=counts)
    require(identity["decision"] == "WORKER_IDENTITY_VERIFIED", "no active verified Workers")
    queue_arn = check_queue(read, account)
    kinds = [kind for kind, count in counts.items() if count]
    if "remote_command" in kinds:
        require(
            bool(re.fullmatch(
                r"[a-z0-9-]+-ats\.iot\.ap-northeast-1\.amazonaws\.com",
                iot_endpoint,
            )),
            "unreviewed IoT Data Endpoint",
        )
    # Campaign currently shares the API application DB principal, and its
    # trust-root pathname has no proven read-only image/volume attestation.
    # Do not label that configuration an independently isolated Worker.
    require(
        "campaign" not in kinds,
        "Campaign still shares the application database role and lacks trusted key delivery",
    )
    if "campaign" in kinds:
        require(
            isinstance(firmware_bucket, str)
            and bool(re.fullmatch(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]+", firmware_bucket))
            and trust_file.startswith("/opt/trust/"),
            "Campaign firmware scope/trust root missing",
        )
    observations: dict[str, Any] = {}
    for kind in kinds:
        db_secret = secrets[kind]
        verify_secret(read, account, DB_NAMES[kind], db_secret, kms_arn)
        observations[kind] = verify_task(
            read, kind, account=account, tenant=tenant, digest=digest, cluster=cluster,
            db_secret=db_secret, redis_secret=redis_secret, kms=kms_arn,
            queue_arn=queue_arn, redis_host=redis_host, iot_endpoint=iot_endpoint,
            firmware_bucket=firmware_bucket, trust_file=trust_file,
            vpc_id=vpc_id, database_sg=database_sg, redis_sg=redis_sg,
        )
    if "remote_command" in kinds:
        verify_secret(read, account, "/connected-vehicle/staging/redis/auth",
                      redis_secret, kms_arn)
    return {
        "decision": "WORKER_IAM_CONFIG_OBSERVED",
        "release_authorized": False,
        "credential_value_verified": False,
        "ota_runtime_verified": False,
        "aws_account_id": account, "region": REGION, "tenant": tenant,
        "image_digest": digest, "sqs_queue_arn": queue_arn, "verified": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "account-id", "cluster", "tenant", "digest", "counts-json",
        "application-secret-arn", "outbox-secret-arn", "remote-secret-arn",
        "redis-secret-arn", "kms-key-arn", "redis-host", "iot-endpoint", "trust-file",
        "vpc-id", "database-sg-id", "redis-sg-id", "source-sha",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--firmware-bucket-arn", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        require(
            not args.output.exists() and not args.output.is_symlink(),
            "evidence already exists",
        )
        require(
            not any(name.startswith("AWS_ENDPOINT_URL") and value
                    for name, value in os.environ.items()),
            "AWS endpoint override forbidden",
        )
        checkout = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True,
            text=True, timeout=10, check=False,
        )
        require(
            bool(re.fullmatch(r"[a-f0-9]{40}", args.source_sha))
            and checkout.returncode == 0
            and checkout.stdout.strip() == args.source_sha,
            "approved source SHA and checkout differ",
        )
        counts = json.loads(args.counts_json)
        require(isinstance(counts, dict), "invalid count payload")
        report = inspect(
            aws, account=args.account_id, cluster=args.cluster, tenant=args.tenant,
            digest=args.digest, counts=counts,
            secrets={
                "outbox": args.outbox_secret_arn,
                "remote_command": args.remote_secret_arn,
                "campaign": args.application_secret_arn,
            },
            redis_secret=args.redis_secret_arn, kms_arn=args.kms_key_arn,
            redis_host=args.redis_host, iot_endpoint=args.iot_endpoint,
            firmware_bucket=args.firmware_bucket_arn or None,
            trust_file=args.trust_file,
            vpc_id=args.vpc_id, database_sg=args.database_sg_id,
            redis_sg=args.redis_sg_id,
        )
        report["source_sha"] = args.source_sha
        report["run_id"] = os.environ.get("GITHUB_RUN_ID", "")
        report["run_attempt"] = os.environ.get("GITHUB_RUN_ATTEMPT", "")
        report["observed_at_utc"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        print("DAY40: IAM and configuration observed; OTA Runtime remains unverified")
        return 0
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        print("DAY40 WORKER BLOCKED: identity/config evidence incomplete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
