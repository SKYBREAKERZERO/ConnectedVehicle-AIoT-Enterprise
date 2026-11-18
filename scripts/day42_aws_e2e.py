"""Real AWS Staging transport and one-ECU campaign acceptance probes.

The runner refuses to act without an explicit live flag, verified STS account,
immutable source checkout, isolated test-vehicle approval and bounded deadlines.
A transport receipt is NOT independently sufficient for a staging release:
separate Outbox/SQS/DB audit and campaign safety gates remain mandatory.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import aiomqtt
import boto3
import httpx2 as httpx
from botocore.config import Config

REGION = "ap-northeast-1"
QUEUE_NAME = "cv-ota-staging-command"
TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ENDPOINT_RE = re.compile(r"[a-z0-9-]+-ats\.iot\.ap-northeast-1\.amazonaws\.com\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class E2EBlocked(ValueError):
    """A Staging safety precondition, missing receipt or invariant failed."""


def require(ok: Any, message: str) -> None:
    if not ok:
        raise E2EBlocked("DAY42 BLOCKED: " + message)


def source_checkout(sha: str) -> None:
    require(bool(re.fullmatch(r"[a-f0-9]{40}", sha)), "unapproved source SHA")
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True,
        text=True, timeout=10, check=False,
    )
    require(result.returncode == 0 and result.stdout.strip() == sha, "checkout SHA drift")


def ensure_tls_api(url: str) -> str:
    parsed = urlsplit(url)
    require(
        parsed.scheme == "https" and bool(parsed.hostname)
        and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        and not parsed.username and not parsed.password and not parsed.query
        and not parsed.fragment and parsed.path in {"", "/"},
        "operator API must be verified HTTPS without URL credentials",
    )
    return url.rstrip("/")


def ensure_loopback_tunnel(url: str) -> str:
    parsed = urlsplit(url)
    require(
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"}
        and parsed.port is not None and 1 <= parsed.port <= 65535
        and not parsed.username and not parsed.password and not parsed.query
        and not parsed.fragment and parsed.path in {"", "/"},
        "ECU simulator must use an approved loopback-only private tunnel",
    )
    return url.rstrip("/")


def admission(args: argparse.Namespace) -> dict[str, str]:
    require(args.live, "live execution requires explicit --live")
    require(
        os.environ.get("DAY42_APPROVED_STAGING") == "true",
        "protected Staging runner approval is absent",
    )
    require(
        not any(k.startswith("AWS_ENDPOINT_URL") and v for k, v in os.environ.items()),
        "LocalStack/AWS endpoint override is forbidden",
    )
    source_checkout(args.source_sha)
    require(
        bool(re.fullmatch(r"[0-9]{12}", args.account_id))
        and bool(TENANT_RE.fullmatch(args.tenant))
        and args.tenant.startswith("e2e-"),
        "Staging account or isolated e2e tenant invalid",
    )
    require(UUID(args.vehicle).version == 4, "test vehicle must be canonical UUIDv4")
    require(
        args.approved_vehicle_file.is_file()
        and not args.approved_vehicle_file.is_symlink(),
        "approved test vehicle manifest missing",
    )
    approved = json.loads(args.approved_vehicle_file.read_text(encoding="utf-8"))
    require(
        approved == {
            "environment": "aws-staging", "account_id": args.account_id,
            "tenant_id": args.tenant, "vehicle_id": args.vehicle,
            "test_only": True, "physical_vehicle": False,
        },
        "vehicle is not explicitly registered as a virtual-only Staging fixture",
    )
    require(not args.output.exists() and not args.output.is_symlink(), "output receipt exists")
    identity = boto3.client("sts", region_name=REGION).get_caller_identity()
    require(identity.get("Account") == args.account_id, "AWS STS account mismatch")
    caller = str(identity.get("Arn", ""))
    require(
        caller.startswith(f"arn:aws:sts::{args.account_id}:assumed-role/")
        and ("e2e" in caller.lower() or "acceptance" in caller.lower()),
        "independent approved e2e runner role required",
    )
    return {"source_sha": args.source_sha, "aws_account_id": args.account_id,
            "region": REGION, "tenant_id": args.tenant, "vehicle_id": args.vehicle}


def read_token(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "token file not available")
    token = path.read_text(encoding="utf-8").strip()
    require(32 <= len(token) <= 16384 and "\n" not in token, "invalid OIDC token")
    return token


def checked_queue(account: str) -> str:
    sqs = boto3.client("sqs", region_name=REGION, config=Config(
        connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1},
    ))
    url = sqs.get_queue_url(QueueName=QUEUE_NAME)["QueueUrl"]
    require(url == f"https://sqs.{REGION}.amazonaws.com/{account}/{QUEUE_NAME}",
            "unapproved SQS queue")
    attrs = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn", "SqsManagedSseEnabled", "RedrivePolicy"],
    )["Attributes"]
    require(
        attrs.get("QueueArn") == f"arn:aws:sqs:{REGION}:{account}:{QUEUE_NAME}"
        and attrs.get("SqsManagedSseEnabled") == "true",
        "SQS ARN or encryption drift",
    )
    redrive = json.loads(attrs.get("RedrivePolicy", "{}"))
    require(
        redrive.get("deadLetterTargetArn")
        == f"arn:aws:sqs:{REGION}:{account}:{QUEUE_NAME}-dlq"
        and str(redrive.get("maxReceiveCount")) == "5",
        "SQS DLQ policy drift",
    )
    return attrs["QueueArn"]


def base_receipt(args: argparse.Namespace, preflight: dict[str, str]) -> dict[str, Any]:
    return {
        **preflight,
        "schema": "day42.real-aws-staging-e2e.v1",
        "scenario": args.scenario,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "production_approved": False,
        "physical_ecu_tested": False,
        "evidence_scope": "real-aws-staging-and-virtual-test-ecu",
    }


async def remote_transport(args: argparse.Namespace, receipt: dict[str, Any]) -> None:
    api = ensure_tls_api(args.api_url)
    require(bool(ENDPOINT_RE.fullmatch(args.iot_endpoint)), "invalid IoT Data-ATS endpoint")
    endpoint = boto3.client("iot", region_name=REGION).describe_endpoint(
        endpointType="iot:Data-ATS"
    )["endpointAddress"]
    require(endpoint == args.iot_endpoint, "IoT endpoint is not this AWS account's ATS endpoint")
    for path in (args.iot_cert, args.iot_key, args.iot_ca):
        require(path.is_file() and not path.is_symlink(), "IoT simulator TLS key/cert missing")
    queue_arn = await asyncio.to_thread(checked_queue, args.account_id)
    topic = f"tenants/{args.tenant}/vehicles/{args.vehicle}/commands"
    ssl_params = aiomqtt.TLSParameters(
        ca_certs=str(args.iot_ca), certfile=str(args.iot_cert),
        keyfile=str(args.iot_key), cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    token = read_token(args.operator_token_file)
    async with aiomqtt.Client(
        hostname=args.iot_endpoint, port=8883, tls_params=ssl_params,
        identifier="e2e-" + uuid4().hex[:16],
    ) as mqtt:
        await mqtt.subscribe(topic, qos=1)
        # Subscribe BEFORE issuing an API command to avoid racing IoT delivery.
        async with httpx.AsyncClient(timeout=10, verify=True) as http:
            response = await http.post(
                api + f"/vehicles/{args.vehicle}/commands",
                headers={"Authorization": "Bearer " + token,
                         "Idempotency-Key": "day42-" + uuid4().hex},
                json={"command_type": "lock"},
            )
        require(response.status_code == 202, "real API rejected isolated test command")
        result = response.json()
        command_id = str(UUID(result["command_id"]))
        require(
            result.get("vehicle_id") == args.vehicle
            and result.get("created") is True
            and result.get("status") == "requested",
            "API response does not prove a new durable command",
        )

        async def await_message() -> dict[str, Any]:
            async for message in mqtt.messages:
                if str(message.topic) != topic:
                    continue
                raw = bytes(message.payload)
                require(len(raw) <= 131072, "oversized IoT delivery")
                data = json.loads(raw)
                if data.get("command_id") != command_id:
                    continue
                require(
                    data.get("tenant_id") == args.tenant
                    and data.get("vehicle_id") == args.vehicle
                    and data.get("command_type") == "lock"
                    and data.get("schema_version") == "1.0",
                    "IoT delivery tenant/payload mismatch",
                )
                return {"topic": topic, "command_id": command_id,
                        "payload_sha256": hashlib.sha256(raw).hexdigest()}
            raise E2EBlocked("IoT subscriber closed before matching delivery")

        delivered = await asyncio.wait_for(await_message(), timeout=args.deadline_seconds)
    receipt["real_sqs_queue_arn"] = queue_arn
    receipt["api_command_created"] = True
    receipt["iot_tls_subscriber_received"] = True
    receipt["iot_delivery"] = delivered
    receipt["outbox_db_audit_verified"] = False
    receipt["sqs_message_specific_audit_verified"] = False
    receipt["decision"] = "REAL_AWS_TRANSPORT_OBSERVED_AUDIT_REQUIRED"


async def campaign_ecu(args: argparse.Namespace, receipt: dict[str, Any]) -> None:
    api = ensure_tls_api(args.api_url)
    tunnel = ensure_loopback_tunnel(args.local_api_tunnel)
    require(args.campaign_id is not None and args.ecu_id is not None, "Campaign/ECU IDs required")
    campaign_id, ecu_id = str(UUID(args.campaign_id)), str(UUID(args.ecu_id))
    require(
        args.expected_job_id is not None
        and bool(re.fullmatch(r"[0-9a-f-]{36}", args.expected_job_id)),
        "expected immutable OTA Job ID required",
    )
    for path in (
        args.ecu_token_file, args.ecu_private_key, args.trusted_keys,
        args.bootstrap_image,
    ):
        require(path is not None and path.is_file() and not path.is_symlink(),
                "simulated ECU trust material missing")
    require(
        args.state_dir is not None and not args.state_dir.is_symlink(),
        "isolated virtual ECU state directory required",
    )
    token = read_token(args.operator_token_file)
    headers = {"Authorization": "Bearer " + token}

    async def api_get(path: str) -> Any:
        async with httpx.AsyncClient(timeout=10, verify=True) as http:
            r = await http.get(api + path, headers=headers)
        require(r.status_code == 200, "actual AWS API read/reconciliation failed")
        return r.json()

    async def target() -> dict[str, Any]:
        rows = await api_get(f"/v2/ota/campaigns/{campaign_id}/targets?limit=100")
        require(isinstance(rows, list), "malformed Campaign targets response")
        selected = [row for row in rows if row.get("ecu_id") == ecu_id]
        require(len(selected) == 1, "test ECU not in frozen Campaign targets")
        row = selected[0]
        require(
            row.get("vehicle_id") == args.vehicle
            and row.get("job_id") == args.expected_job_id,
            "Campaign job/vehicle binding drift",
        )
        return row

    view = await api_get(f"/v2/ota/campaigns/{campaign_id}")
    require(
        view.get("target_count") == 1
        and view.get("snapshot_sha256") is not None
        and view.get("status") in {"running", "completed"},
        "Campaign is not approved frozen single-test-ECU rollout",
    )
    deadline = asyncio.get_running_loop().time() + args.deadline_seconds
    while True:
        row = await target()
        if row.get("dispatched"):
            break
        require(asyncio.get_running_loop().time() < deadline,
                "real Campaign Worker did not dispatch approved job")
        await asyncio.sleep(2)
    require(row.get("job_status") in {"verified", "downloading", "installing", "succeeded"},
            "real Campaign Worker dispatched unexpected job state")

    # A separately approved private SSM/port-forward endpoint terminates TLS
    # upstream. The simulator itself keeps its strict loopback HTTP restriction.
    cmd = [
        sys.executable, "-m", "simulators.ota_device",
        "--base-url", tunnel, "--tenant", args.tenant,
        "--vehicle", args.vehicle, "--ecu", ecu_id,
        "--device-id", args.device_id, "--ecu-type", args.ecu_type,
        "--hardware-version", args.hardware_version,
        "--job", args.expected_job_id,
        "--state-dir", str(args.state_dir),
        "--token-file", str(args.ecu_token_file),
        "--trusted-keys", str(args.trusted_keys),
        "--ecu-private-key", str(args.ecu_private_key),
        "--bootstrap-image", str(args.bootstrap_image),
        "--bootstrap-sha256", args.bootstrap_sha256,
        "--bootstrap-version", args.bootstrap_version,
        "--bootstrap-security-version", str(args.bootstrap_security_version),
    ]
    # Never pass a cloud password, AWS access key or OTA private key as command text.
    result = await asyncio.to_thread(
        subprocess.run, cmd, capture_output=True, text=True,
        timeout=args.deadline_seconds, check=False,
    )
    require(result.returncode == 0, "virtual ECU install or authenticated report failed")
    require(len(result.stdout) <= 32768, "simulator receipt too large")
    simulator_receipt = json.loads(result.stdout)
    # Simulator receipt is supporting evidence; the authoritative outcome is
    # the separate live AWS API read after its signed report was submitted.
    while True:
        row = await target()
        if row.get("job_status") == "succeeded":
            break
        require(asyncio.get_running_loop().time() < deadline,
                "signed ECU report did not reconcile to succeeded job")
        await asyncio.sleep(2)
    final_view = await api_get(f"/v2/ota/campaigns/{campaign_id}")
    require(
        final_view.get("succeeded") == 1
        and final_view.get("failed") == 0
        and final_view.get("job_count") == 1,
        "Campaign counters do not reconcile with actual successful ECU job",
    )
    receipt["campaign_id"] = campaign_id
    receipt["job_id"] = args.expected_job_id
    receipt["ecu_id"] = ecu_id
    receipt["snapshot_sha256"] = view["snapshot_sha256"]
    receipt["virtual_ecu_receipt_sha256"] = hashlib.sha256(
        json.dumps(simulator_receipt, sort_keys=True).encode()
    ).hexdigest()
    receipt["real_aws_campaign_report_reconciled"] = True
    receipt["independent_rds_audit_verified"] = False
    receipt["decision"] = "REAL_AWS_CAMPAIGN_ECU_OBSERVED_AUDIT_REQUIRED"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--live", action="store_true")
    p.add_argument("--scenario", choices=("remote", "campaign"), required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--account-id", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--vehicle", required=True)
    p.add_argument("--approved-vehicle-file", required=True, type=Path)
    p.add_argument("--api-url", required=True)
    p.add_argument("--operator-token-file", required=True, type=Path)
    p.add_argument("--deadline-seconds", type=int, default=90)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--iot-endpoint", default="")
    p.add_argument("--iot-cert", type=Path)
    p.add_argument("--iot-key", type=Path)
    p.add_argument("--iot-ca", type=Path)
    p.add_argument("--local-api-tunnel", default="")
    p.add_argument("--campaign-id")
    p.add_argument("--ecu-id")
    p.add_argument("--expected-job-id")
    p.add_argument("--device-id")
    p.add_argument("--ecu-type")
    p.add_argument("--hardware-version")
    p.add_argument("--state-dir", type=Path)
    p.add_argument("--ecu-token-file", type=Path)
    p.add_argument("--trusted-keys", type=Path)
    p.add_argument("--ecu-private-key", type=Path)
    p.add_argument("--bootstrap-image", type=Path)
    p.add_argument("--bootstrap-sha256", default="")
    p.add_argument("--bootstrap-version", default="")
    p.add_argument("--bootstrap-security-version", type=int, default=0)
    return p


async def run(args: argparse.Namespace) -> dict[str, Any]:
    require(20 <= args.deadline_seconds <= 300, "bounded E2E timeout must be 20..300 seconds")
    preflight = admission(args)
    receipt = base_receipt(args, preflight)
    if args.scenario == "remote":
        await remote_transport(args, receipt)
    else:
        await campaign_ecu(args, receipt)
    return receipt


def main() -> int:
    args = parser().parse_args()
    try:
        receipt = asyncio.run(run(args))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        print("DAY42: real transport/virtual-ECU receipt written; independent audit still required")
        return 0
    except (E2EBlocked, OSError, ValueError, TypeError, TimeoutError, RuntimeError) as exc:
        print("DAY42 BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
