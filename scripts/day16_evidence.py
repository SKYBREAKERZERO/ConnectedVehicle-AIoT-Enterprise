"""Fail-closed, run-scoped resilience acceptance evidence (local dependencies only)."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from database.credential_audit import AuditSegment, encoded
from database.credential_journal import LifecycleEvent, validate_event_chain

REQUIRED = {
    "recovery-demonstration": {
        "correlated_lifecycle",
        "prometheus_scraped",
        "durable_state_verified",
        "audit_history_preserved",
    },
    "database-disconnect": {
        "backend_terminated",
        "uncommitted_write_rolled_back",
        "fresh_connection_usable",
    },
    "database-lock-timeout": {"bounded_attempts", "sqlstate_recorded", "no_partial_commit"},
    "database-deadlock": {"actual_deadlock", "whole_transaction_retry", "no_partial_commit"},
    "commit-unknown": {
        "actual_commit_response_dropped",
        "durable_result_reconciled",
        "single_command_and_outbox",
    },
    "outbox-crash": {
        "before_send_process_crash",
        "after_send_process_crash",
        "lease_reclaimed",
        "duplicate_delivery_single_dispatch",
        "post_execution_crash_single_business_effect",
    },
    "duplicate-order": {"duplicate_suppressed", "out_of_order_rejected", "no_state_regression"},
    "lease-fencing": {
        "expired_publish_rejected",
        "stale_token_all_updates_rejected",
        "current_owner_succeeds",
    },
    "credential-fencing": {
        "foreign_pending_preserved",
        "foreign_current_preserved",
        "no_stale_password_overwrite",
    },
    "audit-interruption": {
        "checkpoint_failure_recoverable",
        "archive_tampering_rejected",
        "repeated_recovery_safe",
    },
    "database-outage": {
        "connection_failure_detected",
        "bounded_exponential_backoff",
        "recovered_on_next_connection",
    },
    "monitor-outage": {"telemetry_failure_isolated", "database_transaction_succeeds"},
}
SCENARIOS = frozenset(REQUIRED)
ROOT = Path(__file__).resolve().parents[1]


def source_digest() -> str:
    digest = hashlib.sha256()
    for directory in ("enterprise_platform", "connected_vehicle", "database", "scripts", "tests"):
        for path in sorted((ROOT / directory).rglob("*.py")):
            digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def provenance() -> dict[str, str]:
    run_id = os.environ.get("DAY16_EVIDENCE_RUN_ID", "")
    if not run_id.strip():
        raise ValueError("DAY16_EVIDENCE_RUN_ID is required")
    return {
        "run_id": run_id,
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source_sha256": source_digest(),
    }


def write_record(directory: Path, name: str, record: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"day16-{name}.json"
    # Exclusive creation prevents overwriting an earlier or concurrent acceptance.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return path


def evidence(scenario: str, checks: dict[str, bool]) -> None:
    if (
        scenario not in SCENARIOS
        or set(checks) != REQUIRED.get(scenario)
        or any(value is not True for value in checks.values())
    ):
        raise ValueError("Scenario requires nonempty successful assertions")
    write_record(
        Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
        scenario,
        {
            "version": 1,
            "scenario": scenario,
            "checks": checks,
            "provenance": provenance(),
            "environment": "localstack",
            "real_aws_verified": False,
            "generated_at_utc": datetime.now(UTC).isoformat(),
        },
    )


def verify(directory: Path, *, check_existing: bool = False) -> Path:
    expected = provenance()
    records = []
    for scenario in sorted(SCENARIOS):
        path = directory / f"day16-{scenario}.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        checks = record.get("checks")
        if (
            record.get("version") != 1
            or record.get("scenario") != scenario
            or record.get("provenance") != expected
            or record.get("environment") != "localstack"
            or record.get("real_aws_verified") is not False
            or not isinstance(checks, dict)
            or set(checks) != REQUIRED[scenario]
            or any(value is not True for value in checks.values())
        ):
            raise ValueError(f"Invalid or stale Day16 evidence: {scenario}")
        records.append(
            {"scenario": scenario, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
    proof_path = directory / "day16-demo-proof.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if proof.get("provenance") != expected:
        raise ValueError("Stale recovery demonstration")
    validate_demo(proof)
    if check_existing:
        path = directory / "day16-acceptance.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if (
            manifest.get("status") != "passed"
            or manifest.get("provenance") != expected
            or manifest.get("records") != records
            or manifest.get("demo_proof_sha256")
            != hashlib.sha256(proof_path.read_bytes()).hexdigest()
            or manifest.get("real_aws_verified") is not False
        ):
            raise ValueError("Acceptance manifest was modified or is stale")
        return path
    return write_record(
        directory,
        "acceptance",
        {
            "status": "passed",
            "provenance": expected,
            "records": records,
            "demo_proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "real_aws_verified": False,
        },
    )


def validate_demo(proof: dict[str, Any], *, required_cases: set[str] | None = None) -> None:
    expected = required_cases if required_cases is not None else {"lock", "worker"}
    if proof.get("version") != 1 or proof.get("real_aws_verified") is not False:
        raise ValueError("Invalid demonstration environment")
    cases = proof.get("cases", [])
    if len(cases) != len(expected) or {case["case"] for case in cases} != expected:
        raise ValueError("Incomplete demonstration")
    for case in cases:
        operation, fault = case["operation_id"], case["fault_id"]
        if any(re.fullmatch(r"[0-9a-f]{32,64}", value) is None for value in (operation, fault)):
            raise ValueError("Invalid correlation identities")
        duration = case["elapsed_seconds"]
        if (
            not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or not 0 < duration < 60
        ):
            raise ValueError("Unbounded demonstration")
        events = case["events"]
        sequence = [event["sequence"] for event in events]
        if not events or sequence != sorted(set(sequence)):
            raise ValueError("Invalid recovery event sequence")
        states = [event["state"] for event in events]
        if not {"FAULT_DETECTED", "CLASSIFIED", "RETRY", "VERIFY", "RECOVERED"}.issubset(states):
            raise ValueError("Missing observed lifecycle")
        if max(
            index for index, state in enumerate(states) if state == "FAULT_DETECTED"
        ) >= states.index("RECOVERED"):
            raise ValueError("Unresolved fault")
        for event in events:
            if (
                event["operation_id"] != operation
                or event["fault_id"] != fault
                or any(not event.get(key) for key in ("request_id", "correlation_id", "trace_id"))
            ):
                raise ValueError("Uncorrelated recovery event")
            if event.get("component") != ("database" if case["case"] == "lock" else "worker"):
                raise ValueError("Recovery component mismatch")
        samples = {row["state"]: row["value"] for row in case["prometheus_samples"]}
        if any(
            not math.isfinite(samples.get(state, 0)) or samples.get(state, 0) < 1
            for state in ("FAULT_DETECTED", "RETRY", "RECOVERED")
        ):
            raise ValueError("Recovery lifecycle was not scraped")
        if case["case"] == "lock":
            if case["after"] != {"status": "requested", "outbox": 1, "reports": 0} or not any(
                event.get("sqlstate") == "55P03" for event in events
            ):
                raise ValueError("Lock recovery state mismatch")
        elif case["case"] == "worker" and (
            case["after"] != {"status": "succeeded", "outbox": 1, "reports": 2}
            or case["device_executions"] != 1
            or case["device_locked"] != 1
        ):
            raise ValueError("Duplicate or inconsistent execution")
    audit = proof["audit"]
    before, after = audit["archives_before"], audit["archives_after"]
    if (
        not before
        or before != after
        or any(re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in before.values())
        or audit["phase_before"] != "complete"
        or audit["phase_after"] != "complete"
        or audit["sequence_after"] != audit["sequence_before"] + 1
        or audit["checkpoint_unchanged_on_failure"] is not True
        or audit["chain_verified"] is not True
    ):
        raise ValueError("Audit chain regressed or changed history")
    verify_public_audit(audit)


def verify_public_audit(audit: dict[str, Any]) -> None:
    segments = audit["segments"]
    if not 2 <= len(segments) <= 1024:
        raise ValueError("Missing reviewable audit segments")
    rows = {}
    for row in segments:
        digest, record = row["sha256"], row["record"]
        if digest in rows or hashlib.sha256(encoded(record)).hexdigest() != digest:
            raise ValueError("Audit segment digest mismatch")
        rows[digest] = AuditSegment.model_validate(record)
    checkpoint = audit["checkpoint"]
    if (
        checkpoint["phase"] != audit["phase_after"]
        or checkpoint["events"][-1]["sequence"] != audit["sequence_after"]
    ):
        raise ValueError("Audit checkpoint mismatch")
    offset, digest = checkpoint["audit_offset"], checkpoint["audit_archive_sha256"]
    following = [LifecycleEvent.model_validate(row) for row in checkpoint["events"]]
    visited = set()
    while offset:
        if digest not in rows or digest in visited:
            raise ValueError("Broken audit chain")
        visited.add(digest)
        segment = rows[digest]
        if (
            segment.operation_id != checkpoint["operation_id"]
            or segment.offset + len(segment.events) != offset
        ):
            raise ValueError("Audit identity or sequence mismatch")
        validate_event_chain(segment.events + following, segment.offset)
        following = segment.events
        offset, digest = segment.offset, segment.previous_sha256
    if (
        visited != set(rows)
        or visited != set(audit["archives_after"].values())
        or digest is not None
    ):
        raise ValueError("Unlinked audit history")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    parser.add_argument(
        "--check-existing",
        action="store_true",
        help="Verify the immutable manifest without overwriting it",
    )
    args = parser.parse_args()
    print(verify(args.directory, check_existing=args.check_existing))


if __name__ == "__main__":
    main()
