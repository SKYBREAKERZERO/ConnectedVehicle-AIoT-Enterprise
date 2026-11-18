"""Independent real AWS CloudWatch, PostgreSQL RLS and SQS evidence reconciliation.

An operator-supplied live Day42 probe receipt is untrusted until rechecked
against read-only RDS and CloudWatch under an independent staging audit role.
Nothing writes to RDS, queues, IoT or ECS. This is not production approval.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import os
import re
import sys
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import boto3
from botocore.config import Config

from scripts.day42_aws_e2e import REGION, E2EBlocked, require, source_checkout

class ReadOnlyPgConnection(Protocol):
    def transaction(
        self, *, isolation: str, readonly: bool
    ) -> AbstractAsyncContextManager[None]: ...

    async def fetchrow(self, statement: str, *args: object) -> dict[str, Any] | None: ...

    async def fetch(self, statement: str, *args: object) -> list[dict[str, Any]]: ...

    async def fetchval(self, statement: str, *args: object) -> Any: ...

    async def execute(self, statement: str, *args: object) -> str: ...

    async def close(self) -> None: ...


class AsyncPgDriver(Protocol):
    async def connect(
        self, *, dsn: str, timeout: int, command_timeout: int,
        server_settings: dict[str, str],
    ) -> ReadOnlyPgConnection: ...


# asyncpg does not ship PEP 561 metadata in the pinned environment.
# This narrow read-only protocol preserves strict mypy.
asyncpg = cast(AsyncPgDriver, importlib.import_module("asyncpg"))


SQS_ID = re.compile(r"[0-9a-f-]{36}\Z")
EVENT_ID = re.compile(r"remote-command:[0-9a-f-]{36}:requested\Z")
ROLE = "cv_ota_staging_e2e_auditor"


def load_receipt(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "real probe receipt missing")
    raw = path.read_bytes()
    require(len(raw) <= 16384, "oversized probe receipt")
    data = json.loads(raw)
    require(isinstance(data, dict), "malformed probe receipt")
    require(data.get("schema") == "day42.real-aws-staging-e2e.v1", "foreign receipt schema")
    require(
        data.get("production_approved") is False
        and data.get("physical_ecu_tested") is False
        and data.get("evidence_scope") == "real-aws-staging-and-virtual-test-ecu",
        "receipt claims unsupported safety or production outcome",
    )
    require(
        data.get("decision") in {
            "REAL_AWS_TRANSPORT_OBSERVED_AUDIT_REQUIRED",
            "REAL_AWS_CAMPAIGN_ECU_OBSERVED_AUDIT_REQUIRED",
        },
        "missing real AWS transport/ECU evidence",
    )
    return cast(dict[str, Any], data)


def validate_dsn_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "auditor DSN file missing")
    require(path.stat().st_size <= 2048, "oversized auditor DSN")
    if os.name == "posix":
        require(path.stat().st_mode & 0o077 == 0, "auditor DSN must be mode 0600")
    dsn = path.read_text(encoding="utf-8").strip()
    url = urlsplit(dsn)
    params = parse_qs(url.query, keep_blank_values=True)
    require(
        url.scheme in {"postgresql", "postgres"}
        and bool(url.hostname)
        and (url.hostname or "").endswith(".rds.amazonaws.com")
        and url.port == 5432
        and url.username == ROLE
        and params.get("sslmode") == ["verify-full"]
        and len(params.get("sslrootcert", [])) == 1
        and bool(params["sslrootcert"][0]),
        "auditor must use RDS PostgreSQL with verify-full TLS and dedicated role",
    )
    require(Path(params["sslrootcert"][0]).is_file(), "trusted RDS CA file missing")
    return dsn


def validate_receipt(data: dict[str, Any], *, account: str, sha: str, tenant: str) -> None:
    require(
        data.get("source_sha") == sha and data.get("aws_account_id") == account
        and data.get("region") == REGION and data.get("tenant_id") == tenant
        and isinstance(data.get("vehicle_id"), str)
        and isinstance(data.get("observed_at_utc"), str),
        "probe provenance or tenant mismatch",
    )
    stamp = datetime.fromisoformat(data["observed_at_utc"].replace("Z", "+00:00"))
    require(
        stamp.tzinfo is not None and -60 <= (datetime.now(UTC) - stamp).total_seconds()
        <= 1200, "stale/future-dated probe",
    )
    if data.get("scenario") == "remote":
        item = data.get("iot_delivery")
        require(
            data.get("api_command_created") is True
            and data.get("iot_tls_subscriber_received") is True
            and isinstance(item, dict)
            and bool(re.fullmatch(r"[0-9a-f]{64}", item.get("payload_sha256", "")))
            and item.get("topic")
            == f"tenants/{tenant}/vehicles/{data['vehicle_id']}/commands"
            and str(UUID(item.get("command_id", ""))) == item.get("command_id"),
            "IoT device delivery receipt incomplete",
        )
    elif data.get("scenario") == "campaign":
        require(
            data.get("real_aws_campaign_report_reconciled") is True
            and isinstance(data.get("snapshot_sha256"), str)
            and bool(re.fullmatch(r"[a-f0-9]{64}", data["snapshot_sha256"]))
            and bool(re.fullmatch(r"[a-f0-9]{64}", data.get("virtual_ecu_receipt_sha256", "")))
            and data.get("ecu_id") and data.get("job_id") and data.get("campaign_id"),
            "virtual ECU reconciliation receipt incomplete",
        )
    else:
        raise E2EBlocked("DAY42 BLOCKED: unrecognized scenario")


async def database_audit(dsn: str, report: dict[str, Any]) -> dict[str, Any]:
    con = await asyncpg.connect(
        dsn=dsn, timeout=5, command_timeout=5,
        server_settings={"statement_timeout": "5000"},
    )
    try:
        async with con.transaction(isolation="repeatable_read", readonly=True):
            role = await con.fetchrow(
                "SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit "
                "FROM pg_roles WHERE rolname=current_user"
            )
            require(
                role is not None and not any(bool(v) for v in role.values()),
                "database auditor has privileged or inherited capabilities",
            )
            require(await con.fetchval("SELECT current_user") == ROLE,
                    "dedicated read-only audit identity mismatch")
            await con.execute("SELECT set_config('app.tenant_id',$1,true)",
                              report["tenant_id"])
            if report["scenario"] == "remote":
                cid = report["iot_delivery"]["command_id"]
                event = "remote-command:" + cid + ":requested"
                row = await con.fetchrow(
                    "SELECT tenant_id,status,published_at,claim_token,failed_at "
                    "FROM outbox_events WHERE tenant_id=$1 AND event_id=$2",
                    report["tenant_id"], event,
                )
                require(
                    row is not None and row["tenant_id"] == report["tenant_id"]
                    and row["published_at"] is not None
                    and row["failed_at"] is None and row["claim_token"] is None,
                    "Outbox not committed as published",
                )
                command = await con.fetchrow(
                    "SELECT tenant_id,vehicle_id,status FROM remote_commands "
                    "WHERE tenant_id=$1 AND id=$2",
                    report["tenant_id"], cid,
                )
                require(
                    command is not None and command["vehicle_id"] == report["vehicle_id"]
                    and command["tenant_id"] == report["tenant_id"]
                    and command["status"] in {"sent", "succeeded"},
                    "remote worker did not commit the expected command state",
                )
                return {"event_id": event, "outbox_published": True,
                        "remote_command_state": command["status"]}
            row = await con.fetchrow(
                "SELECT t.tenant_id,t.vehicle_id,t.ecu_id,t.job_id,t.dispatched,"
                "j.status FROM ota_campaign_targets t JOIN ota_jobs j "
                "ON j.tenant_id=t.tenant_id AND j.id=t.job_id "
                "WHERE t.tenant_id=$1 AND t.campaign_id=$2 AND t.ecu_id=$3",
                report["tenant_id"], report["campaign_id"], report["ecu_id"],
            )
            require(
                row is not None and row["job_id"] == report["job_id"]
                and row["vehicle_id"] == report["vehicle_id"]
                and row["dispatched"] is True and row["status"] == "succeeded",
                "actual Campaign Job is not the approved successful ECU job",
            )
            reports = await con.fetch(
                "SELECT sequence,payload FROM ota_execution_reports "
                "WHERE tenant_id=$1 AND job_id=$2 ORDER BY sequence",
                report["tenant_id"], report["job_id"],
            )
            require(
                1 <= len(reports) <= 2
                and any(
                    isinstance(row["payload"], (dict, str))
                    and (json.loads(row["payload"]) if isinstance(row["payload"], str)
                         else row["payload"]).get("status") == "succeeded"
                    for row in reports
                ),
                "no durable signed ECU success report in PostgreSQL",
            )
            camp = await con.fetchrow(
                "SELECT status,snapshot_sha256 FROM ota_campaigns "
                "WHERE tenant_id=$1 AND id=$2",
                report["tenant_id"], report["campaign_id"],
            )
            counts = await con.fetchrow(
                "SELECT count(*) AS targets,"
                "count(*) FILTER (WHERE j.id IS NOT NULL) AS jobs,"
                "count(*) FILTER (WHERE j.status='succeeded') AS succeeded,"
                "count(*) FILTER (WHERE j.status='failed') AS failed "
                "FROM ota_campaign_targets t LEFT JOIN ota_jobs j "
                "ON j.tenant_id=t.tenant_id AND j.id=t.job_id "
                "WHERE t.tenant_id=$1 AND t.campaign_id=$2",
                report["tenant_id"], report["campaign_id"],
            )
            require(
                camp is not None and counts is not None
                and counts["targets"] == 1 and counts["jobs"] == 1
                and counts["succeeded"] == 1 and counts["failed"] == 0
                and camp["snapshot_sha256"] == report["snapshot_sha256"],
                "Campaign durable counters or frozen snapshot mismatch",
            )
            return {"campaign_id": report["campaign_id"], "job_id": report["job_id"],
                    "signed_reports": len(reports), "campaign_reconciled": True}
    finally:
        await con.close()


def cloudwatch_sqs_audit(account: str, event_id: str) -> dict[str, str]:
    require(bool(EVENT_ID.fullmatch(event_id)), "invalid remote command event ID")
    logs = boto3.client("logs", region_name=REGION, config=Config(
        connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1},
    ))

    def messages(kind: str, marker: str) -> list[dict[str, Any]]:
        group = f"/ecs/cv-ota-staging/{kind}"
        start = int((datetime.now(UTC) - timedelta(minutes=20)).timestamp() * 1000)
        # No unbounded log enumeration or broad permissions.
        result: list[dict[str, Any]] = []
        token: str | None = None
        for _ in range(8):
            kwargs: dict[str, Any] = {
                "logGroupName": group, "startTime": start,
                "filterPattern": f'"{event_id}"', "limit": 100,
            }
            if token is not None:
                kwargs["nextToken"] = token
            batch = logs.filter_log_events(**kwargs)
            for item in batch.get("events", []):
                if marker in str(item.get("message", "")):
                    result.append(item)
            next_token = batch.get("nextToken")
            if not next_token or next_token == token:
                break
            token = next_token
        require(bool(result), "missing real " + kind + " CloudWatch SQS correlation")
        return result

    a = messages("outbox", "outbox_sqs_published")
    b = messages("remote-command", "remote_sqs_ack")
    sent = set()
    acked = set()
    pattern = re.compile(
        rf"event_id={re.escape(event_id)} message_id=([0-9a-f-]{{36}})"
    )
    for item in a:
        match = pattern.search(str(item.get("message", "")))
        if match and SQS_ID.fullmatch(match.group(1)):
            sent.add(match.group(1))
    for item in b:
        content = str(item.get("message", ""))
        match = pattern.search(content)
        if match and "outcome=processed" in content and SQS_ID.fullmatch(match.group(1)):
            acked.add(match.group(1))
    shared = sent & acked
    require(len(shared) == 1, "SQS SendMessage and processed ACK MessageId not matched")
    return {"sqs_message_id": next(iter(shared)),
            "outbox_log_group": "/ecs/cv-ota-staging/outbox",
            "consumer_log_group": "/ecs/cv-ota-staging/remote-command"}


async def audit(args: argparse.Namespace) -> dict[str, Any]:
    require(args.live and os.environ.get("DAY42_APPROVED_STAGING") == "true",
            "protected auditor approval required")
    source_checkout(args.source_sha)
    require(
        not any(name.startswith("AWS_ENDPOINT_URL") and value
                for name, value in os.environ.items()),
        "AWS endpoint override forbidden",
    )
    require(bool(re.fullmatch(r"[0-9]{12}", args.account_id)), "bad staging account")
    identity = boto3.client("sts", region_name=REGION).get_caller_identity()
    require(identity.get("Account") == args.account_id, "STS account mismatch")
    arn = str(identity.get("Arn", ""))
    require(
        arn.startswith(f"arn:aws:sts::{args.account_id}:assumed-role/")
        and ("audit" in arn.lower() or "acceptance" in arn.lower()),
        "independent AWS auditor role required",
    )
    report = load_receipt(args.receipt)
    validate_receipt(report, account=args.account_id, sha=args.source_sha, tenant=args.tenant)
    dsn = validate_dsn_file(args.audit_dsn_file)
    db = await database_audit(dsn, report)
    sqs: dict[str, str] = {}
    if report["scenario"] == "remote":
        sqs = await asyncio.to_thread(
            cloudwatch_sqs_audit, args.account_id, db["event_id"]
        )
    return {
        "schema": "day42.real-aws-staging-audit.v1",
        "decision": "REAL_AWS_E2E_AUDITED",
        "source_sha": args.source_sha,
        "aws_account_id": args.account_id, "region": REGION,
        "scenario": report["scenario"], "tenant_id": args.tenant,
        "vehicle_id": report["vehicle_id"],
        "probe_receipt_sha256": hashlib.sha256(args.receipt.read_bytes()).hexdigest(),
        "db": db, "cloudwatch_sqs": sqs,
        "production_approved": False,
        "physical_ecu_tested": False,
        "observed_at_utc": datetime.now(UTC).isoformat(),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--live", action="store_true")
    for name in ("account-id", "source-sha", "tenant"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--audit-dsn-file", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "audit receipt exists")
        result = asyncio.run(audit(args))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print("DAY42: live AWS E2E audit observed; staging release remains separately gated")
        return 0
    except (E2EBlocked, OSError, ValueError, TypeError, TimeoutError) as exc:
        print("DAY42 BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
