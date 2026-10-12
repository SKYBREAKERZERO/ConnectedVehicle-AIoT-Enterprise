"""Opt-in AWS AssumeRole probes. No resource creation and no Secret values in reports."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

RUNTIMES = {"api", "outbox", "remote-command"}
DENIED = {"AccessDenied", "AccessDeniedException"}


def validate_target(target: dict[str, Any]) -> None:
    account, region = target.get("account", ""), target.get("region", "")
    if (
        not isinstance(account, str)
        or re.fullmatch(r"[0-9]{12}", account) is None
        or account == "000000000000"
        or not isinstance(region, str)
        or re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9][0-9]*", region) is None
        or not target.get("profile")
    ):
        raise ValueError("Explicit real AWS account, standard Region and profile required")
    patterns = {
        "roles": rf"arn:aws:iam::{account}:role/[A-Za-z0-9_+=,.@/-]+",
        "secrets": rf"arn:aws:secretsmanager:{region}:{account}:secret:[A-Za-z0-9_+=.@/-]+",
        "kms_keys": rf"arn:aws:kms:{region}:{account}:key/[A-Za-z0-9-]+",
    }
    for field, pattern in patterns.items():
        values = target.get(field, {})
        if (
            not isinstance(values, dict)
            or set(values) != RUNTIMES
            or any(
                not isinstance(value, str) or re.fullmatch(pattern, value) is None
                for value in values.values()
            )
        ):
            raise ValueError(f"{field} requires three account/Region-bound ARNs")
        if field != "kms_keys" and len(set(values.values())) != 3:
            raise ValueError(f"{field} resources must be distinct")
    probes = target.get("kms_ciphertexts", {})
    if probes and set(probes) != RUNTIMES:
        raise ValueError("Optional KMS ciphertext fixtures must cover all three runtimes")
    for value in probes.values():
        if not base64.b64decode(value, validate=True):
            raise ValueError("Empty KMS ciphertext fixture")


def run_probe(
    target: dict[str, Any],
    *,
    execute: bool = False,
    session_factory: Callable[..., Any] = boto3.Session,
) -> dict[str, Any]:
    validate_target(target)
    report: dict[str, Any] = {
        "scope": "aws-assumed-runtime-identities",
        "account": target["account"],
        "region": target["region"],
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "status": "not_executed",
        "iam_enforcement_verified": False,
        "kms_via_secrets_manager_verified": False,
        "direct_kms_boundary_verified": False,
        "secret_access": [],
        "direct_kms_access": [],
        "errors": [],
    }
    if not execute:
        return report
    if any(name.startswith("AWS_ENDPOINT_URL") for name in os.environ):
        raise ValueError("Real AWS probes forbid endpoint overrides")
    config = cast(Any, Config)(
        connect_timeout=3,
        read_timeout=10,
        retries={"total_max_attempts": 1},
        ignore_configured_endpoint_urls=True,
    )

    def client(session: Any, service: str) -> Any:
        result = session.client(service, region_name=target["region"], config=config)
        host = urlparse(result.meta.endpoint_url).hostname
        if host != f"{service}.{target['region']}.amazonaws.com":
            raise ValueError("Probe requires the official regional AWS endpoint")
        return result

    source = session_factory(profile_name=target["profile"], region_name=target["region"])
    sts = client(source, "sts")
    if sts.get_caller_identity()["Account"] != target["account"]:
        raise ValueError("Source AWS account mismatch; no runtime probes attempted")
    manager = client(source, "secretsmanager")
    kms = client(source, "kms")
    for runtime in sorted(RUNTIMES):
        secret, key = target["secrets"][runtime], target["kms_keys"][runtime]
        metadata = manager.describe_secret(SecretId=secret)
        if (
            metadata["ARN"] != secret
            or kms.describe_key(KeyId=metadata["KmsKeyId"])["KeyMetadata"]["Arn"] != key
        ):
            raise ValueError("Secret customer-managed KMS key binding mismatch")
        ciphertext = target.get("kms_ciphertexts", {}).get(runtime)
        if ciphertext:
            # Prove the supplied fixture is valid before treating a runtime denial
            # as evidence. Plaintext stays in memory and is immediately discarded.
            baseline = kms.decrypt(
                KeyId=key,
                CiphertextBlob=base64.b64decode(ciphertext, validate=True),
                EncryptionContext={"SecretARN": secret},
            )
            if baseline["KeyId"] != key or not baseline.get("Plaintext"):
                raise ValueError("KMS ciphertext fixture validation failed")
            del baseline
    for runtime in sorted(RUNTIMES):
        role = target["roles"][runtime]
        try:
            credentials = sts.assume_role(
                RoleArn=role, RoleSessionName="runtime-acceptance", DurationSeconds=900
            )["Credentials"]
            session = session_factory(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=target["region"],
            )
            del credentials
            identity = client(session, "sts").get_caller_identity()
            expected = f"arn:aws:sts::{target['account']}:assumed-role/{role.rsplit('/', 1)[1]}/"
            if identity["Account"] != target["account"] or not identity["Arn"].startswith(expected):
                raise ValueError("Assumed runtime identity mismatch")
        except ClientError as error:
            report["errors"].append(
                {
                    "runtime": runtime,
                    "check": "assume_role",
                    "code": error.response["Error"]["Code"],
                }
            )
            continue
        runtime_manager = client(session, "secretsmanager")
        for destination in sorted(RUNTIMES):
            decision = "allowed"
            try:
                response = runtime_manager.get_secret_value(SecretId=target["secrets"][destination])
                if response.get("ARN") != target["secrets"][destination] or not (
                    response.get("SecretString") or response.get("SecretBinary")
                ):
                    raise ValueError("Secret read returned no value or mismatched resource")
                del response
            except ClientError as error:
                code = error.response["Error"]["Code"]
                decision = "denied" if code in DENIED else "error"
            report["secret_access"].append(
                {"runtime": runtime, "target": destination, "decision": decision}
            )
            if decision != ("allowed" if runtime == destination else "denied"):
                report["errors"].append(
                    {
                        "runtime": runtime,
                        "check": "secret_access",
                        "target": destination,
                        "decision": decision,
                    }
                )
        ciphertext = target.get("kms_ciphertexts", {}).get(runtime)
        if ciphertext:
            decision = "allowed"
            try:
                client(session, "kms").decrypt(
                    KeyId=target["kms_keys"][runtime],
                    CiphertextBlob=base64.b64decode(ciphertext, validate=True),
                    EncryptionContext={"SecretARN": target["secrets"][runtime]},
                )
            except ClientError as error:
                decision = "denied" if error.response["Error"]["Code"] in DENIED else "error"
            report["direct_kms_access"].append({"runtime": runtime, "decision": decision})
            if decision != "denied":
                report["errors"].append(
                    {"runtime": runtime, "check": "direct_kms", "decision": decision}
                )
    passed = len(report["secret_access"]) == 9 and not report["errors"]
    report.update(
        status="passed" if passed else "failed",
        iam_enforcement_verified=passed,
        kms_via_secrets_manager_verified=passed,
        direct_kms_boundary_verified=passed and len(report["direct_kms_access"]) == 3,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--execute", action="store_true", help="Explicitly enable real AWS read-only probes"
    )
    args = parser.parse_args()
    if args.report and args.report.resolve() == args.target.resolve():
        parser.error("Report must not replace the input target")
    if args.report and args.report.exists():
        parser.error("Report already exists; use a new report path")
    result = run_probe(json.loads(args.target.read_text(encoding="utf-8")), execute=args.execute)
    if args.report:
        with args.report.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
