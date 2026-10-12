"""Repeatable local verification; never claims real AWS IAM enforcement."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from scripts.local_policy import permitted


async def verify_matrix(documents: list[dict[str, Any]], settings: Settings) -> dict[str, Any]:
    if len(documents) != 2 or len({document["tenant_id"] for document in documents}) != 2:
        raise ValueError("Local acceptance requires two distinct tenants")
    summaries = [await verify(document, settings) for document in documents]
    iam: Any = boto3.client(
        "iam",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    targets = [identity for document in documents for identity in document["identities"].values()]
    secrets = []
    decryptions = []
    for document in documents:
        for runtime, identity in document["identities"].items():
            policy = iam.get_role_policy(
                RoleName=identity["role_arn"].rsplit("/", 1)[1], PolicyName="own-database-secret"
            )["PolicyDocument"]
            for target in targets:
                allowed = permitted(
                    policy, "secretsmanager:GetSecretValue", target["secret_arn"], {}
                )
                expected = target["secret_arn"] == identity["secret_arn"]
                if allowed != expected:
                    raise RuntimeError("Local Secret permission matrix failed")
                secrets.append(
                    {
                        "tenant": document["tenant_id"],
                        "runtime": runtime,
                        "target": target["secret_arn"],
                        "decision": "allow" if allowed else "deny",
                    }
                )
            context = {
                "kms:ViaService": f"secretsmanager.{settings.aws_region}.amazonaws.com",
                "kms:EncryptionContext:SecretARN": identity["secret_arn"],
            }
            probes = [
                ("own", document["kms_key_arn"], context, True),
                (
                    "foreign-secret",
                    document["kms_key_arn"],
                    context | {"kms:EncryptionContext:SecretARN": "foreign"},
                    False,
                ),
                ("missing-context", document["kms_key_arn"], {}, False),
                (
                    "wrong-service",
                    document["kms_key_arn"],
                    context | {"kms:ViaService": f"s3.{settings.aws_region}.amazonaws.com"},
                    False,
                ),
                (
                    "wrong-region",
                    document["kms_key_arn"],
                    context | {"kms:ViaService": "secretsmanager.wrong-region.amazonaws.com"},
                    False,
                ),
                ("wrong-key", "foreign-key", context, False),
            ]
            for probe, key, values, expected in probes:
                allowed = permitted(policy, "kms:Decrypt", key, values)
                if allowed != expected:
                    raise RuntimeError("Local KMS permission matrix failed")
                decryptions.append(
                    {
                        "tenant": document["tenant_id"],
                        "runtime": runtime,
                        "probe": probe,
                        "decision": "allow" if allowed else "deny",
                    }
                )
    return {
        "scope": "localstack-only",
        "iam_enforcement_verified": False,
        "configuration_matrix": {"secret": secrets, "kms": decryptions},
        "runtime_and_kms": summaries,
    }


async def verify(document: dict[str, Any], settings: Settings) -> dict[str, Any]:
    if (
        document["scope"] != "localstack-only"
        or settings.cloud_runtime.value != "localstack"
        or not settings.aws_endpoint_url
        or urlparse(settings.aws_endpoint_url).hostname not in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("Verification requires loopback LocalStack")
    arguments: dict[str, Any] = dict(
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    iam: Any = boto3.client("iam", **arguments)
    kms = boto3.client("kms", **arguments)
    manager = boto3.client("secretsmanager", **arguments)
    key_arn = document["kms_key_arn"]
    if not kms.describe_key(KeyId=key_arn)["KeyMetadata"]["Enabled"]:
        raise RuntimeError("Local runtime security contract failed")
    if not kms.get_key_rotation_status(KeyId=key_arn)["KeyRotationEnabled"]:
        raise RuntimeError("Local runtime security contract failed")
    rows = []
    for runtime in DATABASE_USERS:
        identity = document["identities"][runtime]
        role_name = identity["role_arn"].rsplit("/", 1)[1]
        if iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            raise RuntimeError("Local runtime security contract failed")
        if not iam.list_role_policies(RoleName=role_name)["PolicyNames"] == ["own-database-secret"]:
            raise RuntimeError("Local runtime security contract failed")
        policy = iam.get_role_policy(RoleName=role_name, PolicyName="own-database-secret")[
            "PolicyDocument"
        ]
        read, decrypt = policy["Statement"]
        if not read == {
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": identity["secret_arn"],
        }:
            raise RuntimeError("Local runtime security contract failed")
        if not decrypt == {
            "Effect": "Allow",
            "Action": "kms:Decrypt",
            "Resource": key_arn,
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": f"secretsmanager.{settings.aws_region}.amazonaws.com",
                    "kms:EncryptionContext:SecretARN": identity["secret_arn"],
                }
            },
        }:
            raise RuntimeError("Local runtime security contract failed")
        if not manager.describe_secret(SecretId=identity["secret_arn"])["KmsKeyId"] == key_arn:
            raise RuntimeError("Local runtime security contract failed")
        pinned = settings.model_copy(
            update={
                "database_tenant_id": document["tenant_id"],
                "application_database_secret_id": None,
                "outbox_database_secret_id": None,
                "remote_command_database_secret_id": None,
            }
        )
        resolved = await load_runtime_database_settings(pinned, runtime)
        if resolved.database_host not in {"localhost", "127.0.0.1"}:
            raise ValueError("Verification requires loopback database")
        engine = create_database_engine(resolved)
        try:
            await verify_runtime_database_security(engine, runtime, tenant_id=document["tenant_id"])
        finally:
            await engine.dispose()
        rows.append({"runtime": runtime, "login": resolved.database_username, "contract": "passed"})
    context = {"SecretARN": document["identities"]["application"]["secret_arn"]}
    encrypted = kms.encrypt(
        KeyId=key_arn, Plaintext=b"local-context-probe", EncryptionContext=context
    )
    if (
        not kms.decrypt(CiphertextBlob=encrypted["CiphertextBlob"], EncryptionContext=context)[
            "Plaintext"
        ]
        == b"local-context-probe"
    ):
        raise RuntimeError("Local runtime security contract failed")
    try:
        kms.decrypt(
            CiphertextBlob=encrypted["CiphertextBlob"], EncryptionContext={"SecretARN": "foreign"}
        )
    except kms.exceptions.InvalidCiphertextException:
        pass
    else:
        raise RuntimeError("Local KMS accepted wrong context")
    return {
        "tenant_id": document["tenant_id"],
        "roles": rows,
        "iam_policy_configuration": "passed",
        "kms_context_roundtrip": "passed",
        "iam_enforcement_verified": False,
        "scope": "localstack-only",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("document", type=Path)
    args = parser.parse_args()
    document = json.loads(args.document.read_text(encoding="utf-8-sig"))
    print(json.dumps(asyncio.run(verify(document, Settings())), indent=2))


if __name__ == "__main__":
    main()
