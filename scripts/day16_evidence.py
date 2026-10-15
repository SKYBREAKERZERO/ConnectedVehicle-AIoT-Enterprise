"""Fail-closed, run-scoped resilience acceptance evidence (local dependencies only)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REQUIRED = {
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


def verify(directory: Path) -> Path:
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
    return write_record(
        directory,
        "acceptance",
        {
            "status": "passed",
            "provenance": expected,
            "records": records,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "real_aws_verified": False,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    args = parser.parse_args()
    print(verify(args.directory))


if __name__ == "__main__":
    main()
