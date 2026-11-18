"""Live readback of this run's disposable LocalStack deployment, never AWS."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from scripts.iac.day31_evidence import provenance

CHECKS = {
    "sqs_roundtrip",
    "sqs_kms_and_dlq",
    "kms_metadata",
    "secret_kms_metadata",
    "iam_attachment",
    "ota_second_plan",
}


def require_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    if (
        not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint)
        or parsed.port is None
        or not 1 <= parsed.port <= 65535
    ):
        raise ValueError("Day32 deployment probe requires the owned loopback emulator")


def queue_url(endpoint: str, original: str) -> str:
    require_endpoint(endpoint)
    parsed = urlsplit(original)
    if parsed.scheme != "http" or not re.fullmatch(r"/[0-9]{12}/[A-Za-z0-9_-]+", parsed.path):
        raise ValueError("unexpected isolated queue identity")
    if parsed.hostname != "127.0.0.1" and not (parsed.hostname or "").endswith(
        ".localhost.localstack.cloud"
    ):
        raise ValueError("external queue endpoint prohibited")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("unsafe queue URL")
    return endpoint + parsed.path


def probe(endpoint: str, outputs: dict[str, Any], *, ota_verified: bool) -> dict[str, Any]:
    require_endpoint(endpoint)
    if not ota_verified or any(value.get("sensitive") is not False for value in outputs.values()):
        raise ValueError("verified OTA plan and non-sensitive outputs required")
    sdk = importlib.import_module("boto3")
    config = importlib.import_module("botocore.config").Config(
        connect_timeout=3, read_timeout=5, retries={"max_attempts": 1}
    )
    args = dict(
        endpoint_url=endpoint,
        region_name="ap-northeast-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=config,
    )
    sqs = sdk.client("sqs", **args)
    messaging = outputs["remote_command_messaging"]["value"]
    url = queue_url(endpoint, messaging["queue_url"])
    attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    redrive = json.loads(attributes["RedrivePolicy"])
    if (
        attributes["QueueArn"] != messaging["queue_arn"]
        or not attributes.get("KmsMasterKeyId")
        or redrive["deadLetterTargetArn"] != messaging["dead_letter_queue_arn"]
    ):
        raise ValueError("deployed queue metadata differs from Terraform outputs")
    body = "day32-" + uuid4().hex
    sent = sqs.send_message(QueueUrl=url, MessageBody=body)
    found = None
    for _ in range(3):
        messages = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get(
            "Messages", []
        )
        if messages:
            found = messages[0]
            break
    if found is None or found["MessageId"] != sent["MessageId"] or found["Body"] != body:
        raise ValueError("live isolated SQS roundtrip failed")
    sqs.delete_message(QueueUrl=url, ReceiptHandle=found["ReceiptHandle"])
    kms = sdk.client("kms", **args)
    keys = outputs["platform_kms"]["value"]
    for value in keys.values():
        key = kms.describe_key(KeyId=value["key_arn"])["KeyMetadata"]
        if key["Arn"] != value["key_arn"] or key["KeyState"] != "Enabled":
            raise ValueError("live KMS metadata differs from Terraform outputs")
    secrets = sdk.client("secretsmanager", **args)
    secret_entries = outputs["platform_secrets"]["value"]
    for value in secret_entries.values():
        metadata = secrets.describe_secret(SecretId=value["secret_arn"])
        if metadata["ARN"] != value["secret_arn"] or metadata["KmsKeyId"] != value["kms_key_arn"]:
            raise ValueError("live Secret KMS binding differs from Terraform outputs")
    iam = sdk.client("iam", **args)
    identity = outputs["application_runtime_security"]["value"]
    role = iam.get_role(RoleName=identity["role_name"])["Role"]
    policies = iam.list_attached_role_policies(RoleName=identity["role_name"])["AttachedPolicies"]
    if role["Arn"] != identity["role_arn"] or {p["PolicyArn"] for p in policies} != {
        identity["secret_read_policy_arn"]
    }:
        raise ValueError("live application role attachment mismatch")
    if not keys or not secret_entries:
        raise ValueError("empty deployment metadata cannot pass")
    return {
        "version": 1,
        "scope": "localstack_only",
        "provenance": provenance(),
        "checks": {name: True for name in CHECKS},
        "observed_counts": {
            "sqs_messages": 1,
            "kms_keys": len(keys),
            "secrets": len(secret_entries),
            "iam_roles": 1,
        },
        "deployed_roots": ["environments/local", "environments/ota-local"],
        "terraform_outputs_sha256": hashlib.sha256(
            json.dumps(outputs, sort_keys=True).encode()
        ).hexdigest(),
        "real_aws_verified": False,
        "production_apply_enabled": False,
    }
