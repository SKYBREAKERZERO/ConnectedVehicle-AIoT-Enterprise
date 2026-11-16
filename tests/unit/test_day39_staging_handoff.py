"""Day39 Bootstrap: independent AWS identities and no simulated deployment proof."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from scripts import day39_staging_handoff as b

ACCOUNT = "123456789012"
KMS = f"arn:aws:kms:ap-northeast-1:{ACCOUNT}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
VPC = "vpc-12345678"
SHA = "a" * 40


def sample(phase: str) -> dict[str, Any]:
    name = b.SECRETS["application"]
    red = b.SECRETS["redis"]
    result = {
        "sts": {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{b.EXPECTED[phase]}/session",
        },
        "describe-key": {
            "KeyMetadata": {
                "Arn": KMS,
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
            }
        },
        "describe-vpcs": {"Vpcs": [{"VpcId": VPC, "State": "available"}]},
        "describe-db-instances": {
            "DBInstances": [{
                "DBInstanceIdentifier": "cv-ota-staging-postgres",
                "DBInstanceStatus": "available",
                "Engine": "postgres",
                "EngineVersion": "17.7",
                "StorageEncrypted": True,
                "MultiAZ": True,
                "PubliclyAccessible": False,
                "DeletionProtection": True,
                "DBSubnetGroup": {"VpcId": VPC},
            }]
        },
        "describe-replication-groups": {
            "ReplicationGroups": [{
                "ReplicationGroupId": "cv-ota-staging-redis",
                "Status": "available",
                "TransitEncryptionEnabled": True,
                "AtRestEncryptionEnabled": True,
            }]
        },
        name: {
            "Name": name,
            "ARN": f"arn:aws:secretsmanager:ap-northeast-1:{ACCOUNT}:secret:{name}-aaaaaa",
            "KmsKeyId": KMS,
            "VersionIdsToStages": {"a" * 32: ["AWSCURRENT"]},
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "RotationLambdaARN": (
                f"arn:aws:lambda:ap-northeast-1:{ACCOUNT}:function:app-rotator"
            ),
            "LastRotatedDate": "2026-11-16T00:00:00Z",
        },
        red: {
            "Name": red,
            "ARN": f"arn:aws:secretsmanager:ap-northeast-1:{ACCOUNT}:secret:{red}-bbbbbb",
            "KmsKeyId": KMS,
            "VersionIdsToStages": {"b" * 32: ["AWSCURRENT"]},
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "RotationLambdaARN": (
                f"arn:aws:lambda:ap-northeast-1:{ACCOUNT}:function:redis-rotator"
            ),
            "LastRotatedDate": "2026-11-16T00:00:00Z",
        },
    }
    for key in ("outbox", "remote-command"):
        secret_name = b.SECRETS[key]
        metadata = cast(dict[str, Any], copy.deepcopy(result[name]))
        metadata["Name"] = secret_name
        metadata["ARN"] = (
            f"arn:aws:secretsmanager:ap-northeast-1:{ACCOUNT}:secret:{secret_name}-dddddd"
        )
        metadata["RotationLambdaARN"] = (
            f"arn:aws:lambda:ap-northeast-1:{ACCOUNT}:function:{key}-rotator"
        )
        result[secret_name] = metadata
    return result


def reader(data: dict[str, Any]) -> Callable[..., dict[str, Any]]:
    def get(*args: str) -> dict[str, Any]:
        if args[:2] == ("sts", "get-caller-identity"):
            return copy.deepcopy(data["sts"])
        if args[:2] == ("secretsmanager", "describe-secret"):
            return copy.deepcopy(data[args[3]])
        if args[:2] == ("lambda", "get-function-configuration"):
            return {
                "FunctionArn": args[3],
                "State": "Active",
                "LastUpdateStatus": "Successful",
            }
        return copy.deepcopy(data[args[1]])

    return get


@pytest.mark.parametrize("phase", ["foundation", "credentials"])
def test_readonly_handoff_is_not_release_authority(phase: str) -> None:
    output = b.inspect(
        reader(sample(phase)), phase=phase, account=ACCOUNT, kms_arn=KMS,
        vpc=VPC, source_sha=SHA,
    )
    assert output["release_authorized"] is False
    assert output["aws_apply_executed"] is False
    assert output["rotation_functionality_verified"] is False
    assert (output["decision"] == "CREDENTIALS_OBSERVED") is (phase == "credentials")
    if phase == "credentials":
        assert set(output["secrets"]) == {"application", "outbox", "remote-command", "redis"}


def test_wrong_administrator_and_cross_account_denied() -> None:
    data = sample("credentials")
    data["sts"]["Arn"] = (
        f"arn:aws:sts::{ACCOUNT}:assumed-role/cv-ota-staging-deploy/session"
    )
    with pytest.raises(ValueError, match="administrator"):
        b.inspect(reader(data), phase="credentials", account=ACCOUNT, kms_arn=KMS,
                  vpc=VPC, source_sha=SHA)
    with pytest.raises(ValueError, match="foreign/invalid"):
        b.validate_target(ACCOUNT, KMS.replace(ACCOUNT, "999999999999"), VPC, SHA)


@pytest.mark.parametrize("mutation", [
    "missing-rotation", "foreign-lambda", "no-current", "pending",
    "no-rotation-date", "wrong-kms", "disabled-rds", "redis-no-tls",
])
def test_real_aws_prerequisites_fail_closed(mutation: str) -> None:
    data = sample("credentials")
    secret = data[b.SECRETS["application"]]
    if mutation == "missing-rotation":
        secret["RotationEnabled"] = False
    elif mutation == "foreign-lambda":
        secret["RotationLambdaARN"] = secret["RotationLambdaARN"].replace(
            ACCOUNT, "999999999999"
        )
    elif mutation == "no-current":
        secret["VersionIdsToStages"] = {"a" * 32: ["AWSPREVIOUS"]}
    elif mutation == "pending":
        secret["VersionIdsToStages"]["c" * 32] = ["AWSPENDING"]
    elif mutation == "no-rotation-date":
        secret["LastRotatedDate"] = None
    elif mutation == "wrong-kms":
        secret["KmsKeyId"] = KMS.replace(ACCOUNT, "999999999999")
    elif mutation == "disabled-rds":
        data["describe-db-instances"]["DBInstances"][0]["PubliclyAccessible"] = True
    elif mutation == "redis-no-tls":
        data["describe-replication-groups"]["ReplicationGroups"][0][
            "TransitEncryptionEnabled"
        ] = False
    with pytest.raises(ValueError, match="DAY39 BLOCKED"):
        b.inspect(reader(data), phase="credentials", account=ACCOUNT, kms_arn=KMS,
                  vpc=VPC, source_sha=SHA)


def test_no_live_flag_cannot_generate_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    output = tmp_path / "evidence.json"
    monkeypatch.setattr(sys, "argv", [
        "day39", "--phase", "foundation", "--account-id", ACCOUNT,
        "--data-kms-key-arn", KMS, "--vpc-id", VPC,
        "--source-sha", SHA, "--output", str(output),
    ])
    monkeypatch.setattr(b, "aws_json", lambda *args: pytest.fail("AWS called"))
    assert b.main() == 1
    assert not output.exists()
