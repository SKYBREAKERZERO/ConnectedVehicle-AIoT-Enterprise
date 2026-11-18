"""Fail-closed Day42 real AWS E2E probes; no live AWS calls in CI."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3
import pytest

from scripts import day42_aws_e2e as probe
from scripts import day42_e2e_audit as audit

ACCOUNT = "123456789012"
SOURCE = "a" * 40
TENANT = "e2e-staging-test"
VEHICLE = str(uuid4())
COMMAND = str(uuid4())


def good_receipt() -> dict[str, Any]:
    return {
        "schema": "day42.real-aws-staging-e2e.v1",
        "scenario": "remote",
        "decision": "REAL_AWS_TRANSPORT_OBSERVED_AUDIT_REQUIRED",
        "source_sha": SOURCE,
        "aws_account_id": ACCOUNT,
        "region": probe.REGION,
        "tenant_id": TENANT,
        "vehicle_id": VEHICLE,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "api_command_created": True,
        "iot_tls_subscriber_received": True,
        "production_approved": False,
        "physical_ecu_tested": False,
        "evidence_scope": "real-aws-staging-and-virtual-test-ecu",
        "iot_delivery": {
            "command_id": COMMAND,
            "topic": f"tenants/{TENANT}/vehicles/{VEHICLE}/commands",
            "payload_sha256": "b" * 64,
        },
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com",
        "https://127.0.0.1",
        "https://localhost",
        "https://user:secret@api.example.com",
        "https://api.example.com/secret",
        "https://api.example.com?token=abc",
        "https://api.example.com/#admin",
    ],
)
def test_remote_operator_api_refuses_unsafe_urls(url: str) -> None:
    with pytest.raises(probe.E2EBlocked, match="HTTPS"):
        probe.ensure_tls_api(url)


def test_https_operator_api_allowed() -> None:
    assert probe.ensure_tls_api("https://staging-api.example.com/") == (
        "https://staging-api.example.com"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:9000",
        "http://api.example.com:9000",
        "http://localhost:9000",
        "http://127.0.0.1",
        "http://127.0.0.1:9000/path",
        "http://127.0.0.1:9000?skip_tls=true",
        "http://user@127.0.0.1:9000",
    ],
)
def test_simulator_loopback_tunnel_boundary(url: str) -> None:
    with pytest.raises(probe.E2EBlocked, match="loopback"):
        probe.ensure_loopback_tunnel(url)


def test_simulator_accepts_only_explicit_loopback_tunnel() -> None:
    assert probe.ensure_loopback_tunnel("http://127.0.0.1:9000/") == (
        "http://127.0.0.1:9000"
    )


def test_live_run_blocked_without_protected_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DAY42_APPROVED_STAGING", raising=False)
    namespace = argparse.Namespace(live=False)
    with pytest.raises(probe.E2EBlocked, match="explicit --live"):
        probe.admission(namespace)


def test_live_run_never_uses_localstack_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("DAY42_APPROVED_STAGING", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:4566")
    monkeypatch.setattr(probe, "source_checkout", lambda _: None)
    file = tmp_path / "vehicle.json"
    file.write_text("{}", encoding="utf-8")
    namespace = argparse.Namespace(
        live=True, source_sha=SOURCE, account_id=ACCOUNT, tenant=TENANT,
        vehicle=VEHICLE, approved_vehicle_file=file, output=tmp_path / "out.json",
    )
    with pytest.raises(probe.E2EBlocked, match="LocalStack"):
        probe.admission(namespace)


def test_approved_test_vehicle_cannot_be_physical_or_foreign(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("DAY42_APPROVED_STAGING", "true")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.setattr(probe, "source_checkout", lambda _: None)
    file = tmp_path / "vehicle.json"
    file.write_text(json.dumps({
        "environment": "aws-staging", "account_id": ACCOUNT,
        "tenant_id": TENANT, "vehicle_id": VEHICLE,
        "test_only": True, "physical_vehicle": True,
    }))
    namespace = argparse.Namespace(
        live=True, source_sha=SOURCE, account_id=ACCOUNT, tenant=TENANT,
        vehicle=VEHICLE, approved_vehicle_file=file, output=tmp_path / "out.json",
    )
    with pytest.raises(probe.E2EBlocked, match="virtual-only"):
        probe.admission(namespace)


def test_probe_receipt_requires_real_delivery_not_ecs_running(tmp_path: Path) -> None:
    receipt = good_receipt()
    path = tmp_path / "real.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    actual = audit.load_receipt(path)
    audit.validate_receipt(actual, account=ACCOUNT, sha=SOURCE, tenant=TENANT)
    for mutation in (
        {"iot_tls_subscriber_received": False},
        {"decision": "WORKER_IDENTITY_VERIFIED"},
        {"physical_ecu_tested": True},
        {"source_sha": "f" * 40},
        {"tenant_id": "foreign"},
        {"iot_delivery": {"command_id": COMMAND}},
    ):
        bad = good_receipt()
        bad.update(mutation)
        path.write_text(json.dumps(bad), encoding="utf-8")
        if mutation.get("decision") or mutation.get("physical_ecu_tested"):
            with pytest.raises(probe.E2EBlocked):
                audit.load_receipt(path)
        else:
            with pytest.raises((probe.E2EBlocked, ValueError)):
                audit.validate_receipt(bad, account=ACCOUNT, sha=SOURCE, tenant=TENANT)


def test_campaign_receipt_must_include_signed_virtual_ecu_and_snapshot() -> None:
    good = good_receipt()
    good.update({
        "scenario": "campaign",
        "decision": "REAL_AWS_CAMPAIGN_ECU_OBSERVED_AUDIT_REQUIRED",
        "campaign_id": str(uuid4()),
        "ecu_id": str(uuid4()),
        "job_id": str(uuid4()),
        "snapshot_sha256": "c" * 64,
        "virtual_ecu_receipt_sha256": "d" * 64,
        "real_aws_campaign_report_reconciled": True,
    })
    audit.validate_receipt(good, account=ACCOUNT, sha=SOURCE, tenant=TENANT)
    good["real_aws_campaign_report_reconciled"] = False
    with pytest.raises(probe.E2EBlocked, match="receipt incomplete"):
        audit.validate_receipt(good, account=ACCOUNT, sha=SOURCE, tenant=TENANT)


def test_audit_dsn_must_use_dedicated_no_insecure_tls(tmp_path: Path) -> None:
    f = tmp_path / "dsn"
    f.write_text("postgresql://postgres:password@localhost:5432/db", encoding="utf-8")
    f.chmod(0o600)
    with pytest.raises(probe.E2EBlocked, match="verify-full"):
        audit.validate_dsn_file(f)
    ca = tmp_path / "rds.pem"
    ca.write_text("test-only-ca")
    f.write_text(
        "postgresql://cv_ota_staging_e2e_auditor:secret@"
        "db.abcdef.ap-northeast-1.rds.amazonaws.com:5432/app?"
        f"sslmode=verify-full&sslrootcert={ca}"
    )
    f.chmod(0o600)
    assert audit.validate_dsn_file(f).startswith("postgresql://")


class FakeLogs:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.mismatch = mismatch

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        eid = "remote-command:" + COMMAND + ":requested"
        if kwargs["logGroupName"].endswith("/outbox"):
            return {"events": [{
                "message": f"outbox_sqs_published event_id={eid} message_id="
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            }]}
        return {"events": [{
            "message": f"remote_sqs_ack event_id={eid} message_id="
            + ("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" if self.mismatch else
               "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            + " outcome=processed",
        }]}


def test_independent_cloudwatch_correlates_exact_sqs_message_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: FakeLogs())
    result = audit.cloudwatch_sqs_audit(ACCOUNT, "remote-command:" + COMMAND + ":requested")
    assert result["sqs_message_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    monkeypatch.setattr(
        boto3, "client", lambda *args, **kwargs: FakeLogs(mismatch=True)
    )
    with pytest.raises(probe.E2EBlocked, match="not matched"):
        audit.cloudwatch_sqs_audit(ACCOUNT, "remote-command:" + COMMAND + ":requested")


def test_e2e_audit_never_accepts_status_only() -> None:
    source = (Path(__file__).resolve().parents[2] /
              "scripts/day42_e2e_audit.py").read_text(encoding="utf-8")
    assert "ota_execution_reports" in source
    assert "outbox_events" in source
    assert "remote_commands" in source
    assert "cloudwatch_sqs_audit" in source
    assert '"REAL_AWS_E2E_AUDITED"' in source
    assert "ecs_running" not in source


def test_business_workers_emit_matching_correlation_keys() -> None:
    root = Path(__file__).resolve().parents[2]
    outbox = (root / "enterprise_platform/reliability/outbox_dispatcher.py").read_text()
    remote = (root / "connected_vehicle/remote_command/sqs_worker.py").read_text()
    assert "outbox_sqs_published event_id=%s message_id=%s" in outbox
    assert "remote_sqs_ack event_id=%s message_id=%s outcome=processed" in remote
