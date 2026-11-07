"""Day37: zero-credential configuration gate, followed by read-only AWS prerequisite checks.

Does not create resources, acquire credentials, inspect secret VALUES or authorize production.
The six modes map to six fixed, mutually distinct IAM role names and OIDC environments.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

REGION = "ap-northeast-1"
REPOSITORY = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
MODES = ("plan", "bootstrap", "publish", "deploy", "verify", "recovery")
ACCOUNT = re.compile(r"[0-9]{12}\Z")
VPC = re.compile(r"vpc-[0-9a-f]{8,17}\Z")
SUBNET = re.compile(r"subnet-[0-9a-f]{8,17}\Z")
SG = re.compile(r"sg-[0-9a-f]{8,17}\Z")
DOMAIN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9.-]{3,252}\Z")
REPO = re.compile(r"[a-z0-9][a-z0-9._/-]{1,120}\Z")
ROOT_DIR = Path(__file__).resolve().parents[1]


def required(env: Mapping[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value or value in {"None", "null", "REPLACE_ME", "000000000000"}:
        raise ValueError(f"BLOCKED: required Day37 configuration missing: {key}")
    return value


def url(value: str, key: str) -> None:
    item = urlsplit(value)
    if (
        item.scheme != "https"
        or not item.hostname
        or item.username
        or item.password
        or item.hostname.endswith((".invalid", ".example", ".test"))
        or item.hostname in {"localhost", "token.actions.githubusercontent.com"}
        or item.fragment
    ):
        raise ValueError("BLOCKED: invalid application OIDC URL: " + key)


def config(mode: str, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    if mode not in MODES:
        raise ValueError("BLOCKED: unknown Day37 mode")
    if (
        env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or env.get("GITHUB_REPOSITORY") != REPOSITORY
        or env.get("GITHUB_REF") != "refs/heads/main"
        or not re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", ""))
    ):
        raise ValueError("BLOCKED: only protected-main manual workflow is eligible")
    account = required(env, "DAY37_ACCOUNT_ID")
    if not ACCOUNT.fullmatch(account) or account == "0" * 12:
        raise ValueError("BLOCKED: expected 12-digit non-placeholder staging account")
    role = required(env, "DAY37_ROLE_ARN")
    role_name = "cv-ota-staging-" + mode
    if role != f"arn:aws:iam::{account}:role/{role_name}":
        raise ValueError("BLOCKED: mode-specific IAM role ARN mismatch: " + mode)
    if env.get("TF_VAR_aws_region", REGION) != REGION:
        raise ValueError("BLOCKED: non-staging region")
    if env.get("TF_VAR_aws_account_id") not in {None, account}:
        raise ValueError("BLOCKED: Terraform/STS AWS account conflict")
    result: dict[str, Any] = {
        "mode": mode,
        "account": account,
        "region": REGION,
        "role": role,
        "github_environment": "aws-staging-" + mode,
    }
    if mode in {"plan", "bootstrap", "publish", "deploy", "recovery"}:
        bucket = required(env, "DAY37_PLAN_BUCKET")
        prefix = required(env, "DAY37_PLAN_PREFIX").strip("/")
        kms = required(env, "DAY37_PLAN_KMS_ARN")
        if (
            "staging" not in bucket
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{3,62}", bucket)
            or not prefix.startswith("connected-vehicle/day37-plans/")
            or ".." in prefix
            or not re.fullmatch(r"[a-z0-9/_-]{12,220}", prefix)
            or kms != required(env, "DAY37_BACKEND_KMS_ARN")
            or not kms.startswith(f"arn:aws:kms:{REGION}:{account}:key/")
        ):
            raise ValueError("BLOCKED: invalid private versioned S3 Plan handoff configuration")
    if mode in {"plan", "bootstrap", "deploy"}:
        for key in (
            "DAY37_BACKEND_BUCKET",
            "DAY37_BACKEND_KEY",
            "DAY37_BACKEND_KMS_ARN",
            "TF_VAR_aws_account_id",
            "TF_VAR_vpc_id",
            "TF_VAR_private_subnet_ids",
            "TF_VAR_alb_security_group_id",
            "TF_VAR_database_security_group_id",
            "TF_VAR_redis_security_group_id",
            "TF_VAR_application_database_secret_arn",
            "TF_VAR_tenant_id",
            "TF_VAR_redis_host",
            "TF_VAR_oidc_issuer",
            "TF_VAR_oidc_jwks_url",
            "TF_VAR_oidc_audience",
        ):
            required(env, key)
        if not required(env, "DAY37_BACKEND_KEY").startswith("connected-vehicle/ota-staging/"):
            raise ValueError("BLOCKED: Terraform State key outside staging scope")
        if ".." in env["DAY37_BACKEND_KEY"] or not re.fullmatch(
            r"[a-zA-Z0-9/_.-]+", env["DAY37_BACKEND_KEY"]
        ):
            raise ValueError("BLOCKED: unsafe State key")
        if "staging" not in required(env, "DAY37_BACKEND_BUCKET"):
            raise ValueError("BLOCKED: State bucket not staging-scoped")
        if not re.fullmatch(
            rf"arn:aws:kms:{REGION}:{account}:key/[A-Za-z0-9-]+", env["DAY37_BACKEND_KMS_ARN"]
        ):
            raise ValueError("BLOCKED: foreign or invalid backend KMS key")
        if not VPC.fullmatch(env["TF_VAR_vpc_id"]):
            raise ValueError("BLOCKED: invalid VPC ID")
        for key in (
            "TF_VAR_alb_security_group_id",
            "TF_VAR_database_security_group_id",
            "TF_VAR_redis_security_group_id",
        ):
            if not SG.fullmatch(env[key]):
                raise ValueError("BLOCKED: invalid security group ID: " + key)
        try:
            subnet_ids = json.loads(env["TF_VAR_private_subnet_ids"])
        except json.JSONDecodeError as exc:
            raise ValueError("BLOCKED: private subnets must be JSON") from exc
        if (
            not isinstance(subnet_ids, list)
            or len(subnet_ids) < 2
            or len(subnet_ids) != len(set(map(str, subnet_ids)))
            or not all(isinstance(x, str) and SUBNET.fullmatch(x) for x in subnet_ids)
        ):
            raise ValueError("BLOCKED: at least two unique private subnet IDs required")
        result["vpc"] = env["TF_VAR_vpc_id"]
        result["subnets"] = subnet_ids
        result["security_groups"] = [
            env[k]
            for k in (
                "TF_VAR_alb_security_group_id",
                "TF_VAR_database_security_group_id",
                "TF_VAR_redis_security_group_id",
            )
        ]
        secret = env["TF_VAR_application_database_secret_arn"]
        if not secret.startswith(
            f"arn:aws:secretsmanager:{REGION}:{account}:secret:"
        ) or secret.endswith("EXAMPLE"):
            raise ValueError("BLOCKED: database secret must be in exact staging account")
        result["database_secret"] = secret
        for key in ("TF_VAR_oidc_issuer", "TF_VAR_oidc_jwks_url"):
            url(env[key], key)
        if not env["TF_VAR_oidc_audience"].strip():
            raise ValueError("BLOCKED: application OIDC audience missing")
        redis = env["TF_VAR_redis_host"]
        if not DOMAIN.fullmatch(redis) or redis.endswith((".invalid", ".example", ".test")):
            raise ValueError("BLOCKED: invalid Redis private endpoint")
        try:
            ipaddress.ip_address(redis)
        except ValueError:
            pass
        else:
            raise ValueError("BLOCKED: Redis requires DNS endpoint, not raw IP")
        # Naming is intentional: TF_VAR_oidc_* means vehicle API OIDC, never GitHub OIDC.
        # Deployment target group may be unnecessary for infrastructure-only bootstrap.
        if mode in {"plan", "bootstrap", "deploy"}:
            redis_secret = required(env, "TF_VAR_redis_auth_secret_arn")
            if not redis_secret.startswith(f"arn:aws:secretsmanager:{REGION}:{account}:secret:"):
                raise ValueError("BLOCKED: foreign Redis TLS auth secret")
            result["redis_auth_secret"] = redis_secret
        if mode == "deploy":
            required(env, "TF_VAR_alb_target_group_arn")
            if not env["TF_VAR_alb_target_group_arn"].startswith(
                f"arn:aws:elasticloadbalancing:{REGION}:{account}:targetgroup/"
            ):
                raise ValueError("BLOCKED: foreign Staging ALB target group")
            result["target_group"] = env["TF_VAR_alb_target_group_arn"]
        elif env.get("TF_VAR_alb_target_group_arn"):
            if not env["TF_VAR_alb_target_group_arn"].startswith(
                f"arn:aws:elasticloadbalancing:{REGION}:{account}:targetgroup/"
            ):
                raise ValueError("BLOCKED: foreign optional ALB target group")
    if mode in {"publish", "deploy", "verify"}:
        repo = required(env, "DAY37_ECR_REPOSITORY")
        if not REPO.fullmatch(repo) or not repo.startswith("cv-ota-staging/"):
            raise ValueError("BLOCKED: ECR repository outside staging scope")
        result["ecr_repository"] = repo
    if mode in {"bootstrap", "deploy", "verify", "recovery"}:
        name = required(env, "DAY37_CLUSTER")
        if not name.startswith("cv-ota-staging"):
            raise ValueError("BLOCKED: invalid Staging ECS cluster")
        result["cluster"] = name
    if mode in {"deploy", "verify", "recovery"}:
        name = required(env, "DAY37_SERVICE")
        if not name.startswith("cv-ota-staging"):
            raise ValueError("BLOCKED: invalid Staging ECS service")
        result["service"] = name
    if mode == "verify":
        tg = required(env, "DAY37_ALB_TARGET_GROUP_ARN")
        if not tg.startswith(f"arn:aws:elasticloadbalancing:{REGION}:{account}:targetgroup/"):
            raise ValueError("BLOCKED: invalid target group ARN")
        result["target_group"] = tg
    return result


def aws_json(*args: str) -> dict[str, Any]:
    run = subprocess.run(
        ["aws", *args, "--region", REGION, "--output", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if run.returncode != 0:
        raise ValueError("BLOCKED: AWS prerequisite read failed: " + " ".join(args[:2]))
    try:
        body = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("BLOCKED: malformed AWS response") from exc
    if not isinstance(body, dict):
        raise ValueError("BLOCKED: expected AWS JSON object")
    return body


def live(mode: str, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    c = config(mode, env)
    sts = aws_json("sts", "get-caller-identity")
    role_name = "cv-ota-staging-" + mode
    if sts.get("Account") != c["account"] or not sts.get("Arn", "").startswith(
        f"arn:aws:sts::{c['account']}:assumed-role/{role_name}/"
    ):
        raise ValueError(
            "BLOCKED: STS caller account or role does not match reviewed staging identity"
        )
    # Only read-only calls; no provisioning and no secret VALUE reads.
    if mode in {"plan", "bootstrap", "deploy"}:
        vpcs = aws_json("ec2", "describe-vpcs", "--vpc-ids", c["vpc"]).get("Vpcs", [])
        if (
            len(vpcs) != 1
            or vpcs[0].get("VpcId") != c["vpc"]
            or vpcs[0].get("State") != "available"
        ):
            raise ValueError("BLOCKED: actual staging VPC not available")
        subnets = aws_json("ec2", "describe-subnets", "--subnet-ids", *c["subnets"]).get(
            "Subnets", []
        )
        if len(subnets) != len(c["subnets"]) or {s.get("SubnetId") for s in subnets} != set(
            c["subnets"]
        ):
            raise ValueError("BLOCKED: missing staging subnet")
        if any(
            s.get("VpcId") != c["vpc"]
            or s.get("MapPublicIpOnLaunch") is not False
            or s.get("State") != "available"
            for s in subnets
        ):
            raise ValueError("BLOCKED: subnet outside VPC, public-IP enabled, or unavailable")
        if len({s.get("AvailabilityZoneId") for s in subnets}) < 2:
            raise ValueError("BLOCKED: private subnets must span two AZs")
        groups = aws_json(
            "ec2", "describe-security-groups", "--group-ids", *c["security_groups"]
        ).get("SecurityGroups", [])
        if len(groups) != len(c["security_groups"]) or {g.get("GroupId") for g in groups} != set(
            c["security_groups"]
        ):
            raise ValueError("BLOCKED: missing staging security group")
        if any(g.get("VpcId") != c["vpc"] for g in groups):
            raise ValueError("BLOCKED: security group outside staging VPC")
        secret = aws_json("secretsmanager", "describe-secret", "--secret-id", c["database_secret"])
        if secret.get("ARN") != c["database_secret"] or secret.get("DeletedDate"):
            raise ValueError("BLOCKED: application database Secret missing or pending deletion")
        if "AWSCURRENT" not in [
            stage for stages in secret.get("VersionIdsToStages", {}).values() for stage in stages
        ]:
            raise ValueError(
                "BLOCKED: app_user database Secret has no AWSCURRENT credentials version"
            )
        db = aws_json(
            "rds", "describe-db-instances", "--db-instance-identifier", "cv-ota-staging-postgres"
        ).get("DBInstances", [])
        if (
            len(db) != 1
            or db[0].get("DBInstanceStatus") != "available"
            or not db[0].get("StorageEncrypted")
            or not db[0].get("MultiAZ")
            or db[0].get("PubliclyAccessible")
            or not db[0].get("DeletionProtection")
            or db[0].get("Engine") != "postgres"
            or not str(db[0].get("EngineVersion", "")).startswith("17.")
            or db[0].get("DBSubnetGroup", {}).get("VpcId") != c["vpc"]
        ):
            raise ValueError("BLOCKED: healthy private multi-AZ PostgreSQL 17 Foundation missing")
        cache = aws_json(
            "elasticache",
            "describe-replication-groups",
            "--replication-group-id",
            "cv-ota-staging-redis",
        ).get("ReplicationGroups", [])
        if (
            len(cache) != 1
            or cache[0].get("Status") != "available"
            or cache[0].get("TransitEncryptionEnabled") is not True
            or cache[0].get("AtRestEncryptionEnabled") is not True
        ):
            raise ValueError("BLOCKED: TLS encrypted Staging Redis Foundation missing")
        if "redis_auth_secret" in c:
            auth = aws_json(
                "secretsmanager", "describe-secret", "--secret-id", c["redis_auth_secret"]
            )
            if (
                auth.get("ARN") != c["redis_auth_secret"]
                or auth.get("DeletedDate")
                or "AWSCURRENT"
                not in [
                    stage
                    for stages in auth.get("VersionIdsToStages", {}).values()
                    for stage in stages
                ]
            ):
                raise ValueError("BLOCKED: Redis auth Secret lacks reviewed current version")
    if "target_group" in c:
        tgs = aws_json(
            "elbv2", "describe-target-groups", "--target-group-arns", c["target_group"]
        ).get("TargetGroups", [])
        if (
            len(tgs) != 1
            or tgs[0].get("TargetGroupArn") != c["target_group"]
            or tgs[0].get("TargetType") != "ip"
        ):
            raise ValueError("BLOCKED: target group must exist with IP target type")
        if "vpc" in c and tgs[0].get("VpcId") != c["vpc"]:
            raise ValueError("BLOCKED: ALB target group outside staging VPC")
    if "ecr_repository" in c:
        repos = aws_json(
            "ecr", "describe-repositories", "--repository-names", c["ecr_repository"]
        ).get("repositories", [])
        if (
            len(repos) != 1
            or repos[0].get("registryId") != c["account"]
            or repos[0].get("imageTagMutability") != "IMMUTABLE"
        ):
            raise ValueError("BLOCKED: real ECR Repository missing or tag mutability insecure")
    if "cluster" in c and mode != "bootstrap":
        rows = aws_json("ecs", "describe-clusters", "--clusters", c["cluster"]).get("clusters", [])
        if len(rows) != 1 or rows[0].get("status") != "ACTIVE":
            raise ValueError("BLOCKED: target ECS cluster missing")
    return {
        "decision": "STAGING_PREREQUISITES_VERIFIED",
        "mode": mode,
        "account": c["account"],
        "region": REGION,
        "production_authorized": False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("config", "live"))
    p.add_argument("--mode", choices=MODES, required=True)
    args = p.parse_args()
    result = config(args.mode) if args.phase == "config" else live(args.mode)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
