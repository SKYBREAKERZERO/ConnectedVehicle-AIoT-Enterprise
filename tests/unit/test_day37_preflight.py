"""Offline contracts, not real AWS deployment proof."""

from __future__ import annotations

import copy

import pytest

from scripts import day37_preflight as pf


def env(mode: str = "deploy") -> dict[str, str]:
    account = "123456789012"
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": pf.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "DAY37_ACCOUNT_ID": account,
        "DAY37_ROLE_ARN": f"arn:aws:iam::{account}:role/cv-ota-staging-{mode}",
        "DAY37_BACKEND_BUCKET": "cv-ota-staging-state",
        "DAY37_BACKEND_KEY": "connected-vehicle/ota-staging/main.tfstate",
        "DAY37_BACKEND_KMS_ARN": (f"arn:aws:kms:ap-northeast-1:{account}:key/"
            "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        "DAY37_PLAN_BUCKET": "cv-ota-staging-plans",
        "DAY37_PLAN_PREFIX": "connected-vehicle/day37-plans/v1",
        "DAY37_PLAN_KMS_ARN": (f"arn:aws:kms:ap-northeast-1:{account}:key/"
            "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        "TF_VAR_aws_account_id": account,
        "TF_VAR_aws_region": "ap-northeast-1",
        "TF_VAR_vpc_id": "vpc-12345678",
        "TF_VAR_private_subnet_ids": '["subnet-12345678", "subnet-87654321"]',
        "TF_VAR_alb_security_group_id": "sg-12345678",
        "TF_VAR_database_security_group_id": "sg-87654321",
        "TF_VAR_redis_security_group_id": "sg-abcdef12",
        "TF_VAR_application_database_secret_arn": (f"arn:aws:secretsmanager:ap-northeast-1:{account}:secret:"
            "cv/ota-staging/app-a1b2c3"),
        "TF_VAR_tenant_id": "test-tenant-a",
        "TF_VAR_redis_host": "redis.example.internal",
        "TF_VAR_redis_auth_secret_arn": (f"arn:aws:secretsmanager:ap-northeast-1:{account}:secret:"
            "cv/ota-staging/redis-auth-a1b2c3"),
        "TF_VAR_oidc_issuer": "https://login.staging.acme.co.jp",
        "TF_VAR_oidc_jwks_url": "https://login.staging.acme.co.jp/.well-known/jwks.json",
        "TF_VAR_oidc_audience": "cv-staging",
        "TF_VAR_alb_target_group_arn": (f"arn:aws:elasticloadbalancing:ap-northeast-1:{account}:"
            "targetgroup/cv-ota-staging-api/12345678"),
        "DAY37_ECR_REPOSITORY": "cv-ota-staging/vehicle-api",
        "DAY37_CLUSTER": "cv-ota-staging",
        "DAY37_SERVICE": "cv-ota-staging-api",
        "DAY37_ALB_TARGET_GROUP_ARN": (f"arn:aws:elasticloadbalancing:ap-northeast-1:{account}:"
            "targetgroup/cv-ota-staging-api/12345678"),
    }


@pytest.mark.parametrize("mode", pf.MODES)
def test_each_role_is_mode_specific(mode: str) -> None:
    d = pf.config(mode, env(mode))
    assert d["role"].endswith("-" + mode)
    assert d["github_environment"] == "aws-staging-" + mode


@pytest.mark.parametrize(
    "bad, value",
    [
        ("DAY37_ROLE_ARN", "arn:aws:iam::123456789012:role/cv-ota-staging-deploy"),
        ("DAY37_ACCOUNT_ID", "000000000000"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("DAY37_BACKEND_KEY", "../production/main.tfstate"),
        ("DAY37_BACKEND_KMS_ARN", "arn:aws:kms:ap-northeast-1:999999999999:key/a"),
        ("TF_VAR_private_subnet_ids", "not-json"),
        ("TF_VAR_private_subnet_ids", '["subnet-12345678"]'),
        ("TF_VAR_alb_security_group_id", ""),
        (
            "TF_VAR_application_database_secret_arn",
            "arn:aws:secretsmanager:ap-northeast-1:999999999999:secret:prod",
        ),
        ("TF_VAR_oidc_issuer", "https://token.actions.githubusercontent.com"),
        ("TF_VAR_oidc_jwks_url", "http://insecure.local/jwks"),
        ("TF_VAR_redis_host", "redis.staging.internal.invalid"),
    ],
)
def test_fail_closed_pre_credential_config(bad: str, value: str) -> None:
    d = env("plan")
    d[bad] = value
    with pytest.raises(ValueError, match="BLOCKED"):
        pf.config("plan", d)


def test_missing_vars_rejected() -> None:
    d = env("plan")
    d.pop("TF_VAR_vpc_id")
    with pytest.raises(ValueError, match="TF_VAR_vpc_id"):
        pf.config("plan", d)


def test_bootstrap_does_not_require_target_group() -> None:
    d = env("bootstrap")
    d.pop("TF_VAR_alb_target_group_arn")
    assert pf.config("bootstrap", d)["mode"] == "bootstrap"


def test_app_oidc_is_not_github_oidc() -> None:
    d = env("deploy")
    d["TF_VAR_oidc_jwks_url"] = "https://token.actions.githubusercontent.com/keys"
    with pytest.raises(ValueError, match="BLOCKED"):
        pf.config("deploy", d)


def test_live_aws_resources_bind_exact_account_and_vpc(monkeypatch: pytest.MonkeyPatch) -> None:
    e = env("deploy")
    results = {
        "sts": {
            "Account": e["DAY37_ACCOUNT_ID"],
            "Arn": "arn:aws:sts::123456789012:assumed-role/cv-ota-staging-deploy/gh-run-1",
        },
        "describe-vpcs": {"Vpcs": [{"VpcId": e["TF_VAR_vpc_id"], "State": "available"}]},
        "describe-subnets": {
            "Subnets": [
                {
                    "SubnetId": "subnet-12345678",
                    "VpcId": e["TF_VAR_vpc_id"],
                    "MapPublicIpOnLaunch": False,
                    "State": "available",
                    "AvailabilityZoneId": "apne1-az1",
                },
                {
                    "SubnetId": "subnet-87654321",
                    "VpcId": e["TF_VAR_vpc_id"],
                    "MapPublicIpOnLaunch": False,
                    "State": "available",
                    "AvailabilityZoneId": "apne1-az2",
                },
            ]
        },
        "describe-security-groups": {
            "SecurityGroups": [
                {"GroupId": x, "VpcId": e["TF_VAR_vpc_id"]}
                for x in ("sg-12345678", "sg-87654321", "sg-abcdef12")
            ]
        },
        "describe-secret": {
            "ARN": e["TF_VAR_application_database_secret_arn"],
            "VersionIdsToStages": {"1": ["AWSCURRENT"]},
        },
        "describe-db-instances": {
            "DBInstances": [
                {
                    "DBInstanceStatus": "available",
                    "StorageEncrypted": True,
                    "MultiAZ": True,
                    "PubliclyAccessible": False,
                    "DeletionProtection": True,
                    "Engine": "postgres",
                    "EngineVersion": "17.6",
                    "DBSubnetGroup": {"VpcId": e["TF_VAR_vpc_id"]},
                }
            ]
        },
        "describe-replication-groups": {
            "ReplicationGroups": [
                {
                    "Status": "available",
                    "TransitEncryptionEnabled": True,
                    "AtRestEncryptionEnabled": True,
                }
            ]
        },
        "describe-target-groups": {
            "TargetGroups": [
                {
                    "TargetGroupArn": e["TF_VAR_alb_target_group_arn"],
                    "TargetType": "ip",
                    "VpcId": e["TF_VAR_vpc_id"],
                }
            ]
        },
        "describe-repositories": {
            "repositories": [
                {"registryId": e["DAY37_ACCOUNT_ID"], "imageTagMutability": "IMMUTABLE"}
            ]
        },
        "describe-clusters": {"clusters": [{"status": "ACTIVE"}]},
    }

    def fake(*args: str) -> dict:
        if args[1] == "describe-secret" and args[3] == e["TF_VAR_redis_auth_secret_arn"]:
            return {
                "ARN": e["TF_VAR_redis_auth_secret_arn"],
                "VersionIdsToStages": {"1": ["AWSCURRENT"]},
            }
        return copy.deepcopy(results["sts" if args[0] == "sts" else args[1]])

    monkeypatch.setattr(pf, "aws_json", fake)
    assert pf.live("deploy", e)["decision"] == "STAGING_PREREQUISITES_VERIFIED"
    results["describe-subnets"]["Subnets"][1]["VpcId"] = "vpc-99999999"
    with pytest.raises(ValueError, match="BLOCKED"):
        pf.live("deploy", e)


def test_actual_sts_wrong_role_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pf,
        "aws_json",
        lambda *args: {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/cv-ota-staging-publish/id",
        },
    )
    with pytest.raises(ValueError, match="STS caller"):
        pf.live("verify", env("verify"))


def test_workflow_config_checks_precede_each_oidc_step() -> None:
    from pathlib import Path

    import yaml

    y = yaml.safe_load(
        (
            Path(__file__).resolve().parents[2] / ".github/workflows/day37-aws-staging.yml"
        ).read_text()
    )
    for mode in pf.MODES:
        j = y["jobs"][mode]
        assert j["env"]["DAY37_ROLE_ARN"] == "${{ vars.DAY37_" + mode.upper() + "_ROLE_ARN }}"
        steps = j["steps"]
        claims = [
            i
            for i, s in enumerate(steps)
            if s.get("uses", "").startswith("aws-actions/configure-aws-credentials@")
        ]
        assert len(claims) == 1
        before = steps[claims[0] - 1]
        after = steps[claims[0] + 1]
        assert f"day37_preflight config --mode {mode}" in before["run"]
        assert f"day37_preflight live --mode {mode}" in after["run"]
