"""Outbox CI evidence verifier. Stdlib-only: safe for an isolated gate runner.

This verifies provenance *claims* and report integrity. Trust in the tests themselves
requires protected, reviewed workflow/test code and a separate trusted workflow_run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET

SCHEMA = "outbox-ci-evidence-v1"
WORKFLOW = "Outbox Dispatcher Enterprise Runtime"
MAX_BYTES = 10 * 1024 * 1024
MAX_CASES = 10_000

# Each case must appear in the named pytest module, not just anywhere in a report.
REQUIRED: dict[str, dict[str, tuple[str, ...]]] = {
    "contract": {
        "test_reliability_retry": (
            "test_retry_delay_applies_symmetric_jitter",
            "test_retry_raises_after_attempts_exhausted",
        ),
        "test_outbox_dispatcher": (
            "test_dispatcher_persists_retry_with_exponential_backoff",
            "test_retry_exhaustion_is_fenced_and_persisted",
            "test_cost01_closed_claims_full_batch_in_one_call",
            "test_cost01_half_open_claims_only_one_probe",
            "test_cost01_rate_limited_closed_claims_only_one",
            "test_cost01_open_mid_batch_refunds_unattempted_claims",
            "test_cost01c_dispatcher_batches_20_into_two_sends_and_two_updates",
            "test_cost01c_partial_failure_commits_only_success_and_refunds_tail",
            "test_cost01c_lost_batch_response_never_marks_success",
            "test_cost01c_half_open_keeps_individual_probe",
        ),
        "test_outbox_request_reduction": (
            "test_cost01d_idle_backoff_bounds_and_reset_contract",
            "test_cost01d_runtime_empty_poll_uses_adaptive_path",
            "test_cost01d_empty_outbox_does_not_call_sqs",
            "test_cost01d_permanent_failure_does_not_generate_retry_storm",
        ),
        "test_retry_budget": (
            "test_cost02_first_attempt_is_not_charged_retry_budget",
            "test_cost02_budget_denial_defers_only_retries_before_sqs",
            "test_cost02_redis_failure_denies_retries_but_not_first_send",
            "test_cost02_cancellation_refunds_unattempted_claims",
            "test_cost02_zero_budget_never_sends_or_consumes_retry",
            "test_cost02_budget_requires_fenced_deferrer",
            "test_cost02_invalid_budget_policy_is_rejected",
        ),
        "test_retry_guard": (
            "test_retryguard_sqs_permanent_client_error_stops_without_retry",
            "test_retryguard_sqs_transient_client_error_remains_retryable",
            "test_retryguard_sqs_unknown_timeout_retains_at_least_once_contract",
            "test_retryguard_classifier_never_retries_permanent_publish_rejection",
        ),
        "test_sqs_batch": (
            "test_cost01c_sqs_batch_20_events_two_api_calls",
            "test_cost01c_http200_partial_failures_are_mapped_by_id",
            "test_cost01c_invalid_or_missing_batch_response_fails_closed",
            "test_cost01c_fifo_without_group_contract_is_rejected",
        ),
        "test_transaction_recovery": (
            "test_unknown_commit_reads_durable_result_without_replaying",
        ),
        # New tests; not yet implemented on main. The enterprise gate MUST fail until then.
        "test_circuit_breaker": (
            "test_cb001_failure_threshold_opens",
            "test_cb002_open_short_circuits",
            "test_cb003_half_open_single_local_probe",
            "test_cb004_half_open_success_closes",
        ),
    },
    "pg": {
        "test_outbox_claim_lease": (
            "test_two_workers_claim_disjoint_batches_with_skip_locked",
            "test_expired_lease_is_reclaimed_and_stale_token_is_fenced",
            "test_scheduled_retry_is_not_claimed_before_available_at",
        ),
        "test_transactional_outbox": (
            "test_business_and_outbox_commit_atomically",
            "test_business_and_outbox_rollback_atomically",
        ),
        "test_database_runtime_permissions": ("test_real_postgres_runtime_permissions",),
        "test_outbox_circuit_pg": (
            "test_cb003_half_open_single_probe_across_workers",
            "test_cb006_restart_restores_open_state",
            "test_cb008_open_preserves_attempts_and_schedule",
            "test_cb009_runtime_role_isolation_pg17",
            "test_cost01_pg_closed_10_events_one_claim",
            "test_cost01_pg_open_refunds_remaining_without_retry_budget",
            "test_cost01_pg_stale_token_cannot_refund_current_claim",
            "test_cost01c_pg_batch_ack_rejects_stale_token",
        ),
    },
    "cost": {
        "test_outbox_cost_benchmark": ("test_cost01b_real_batch_matrix",),
        "test_outbox_batch_send_localstack": (
            "test_cost01c_real_twenty_events_two_sqs_calls_two_pg_updates",
        ),
    },
    "budget": {
        "test_retry_budget_runtime": (
            "test_cost02_real_redis_multiworker_atomic_global_cap",
            "test_cost02_real_pg_redis_localstack_fleet_retry_defers_without_attempt_loss",
            "test_cost02_real_pg_stale_claim_cannot_defer_or_refund",
        ),
    },
    "retry": {
        "test_invalid_retry_suppression": (
            "test_invalid_retry_sender_fault_is_terminal_but_throttle_is_delayed",
            "test_invalid_retry_lost_response_does_not_ack_or_hot_loop",
        ),
    },
    "delivery": {
        "test_localstack_sqs_dlq": ("test_localstack_sqs_redrives_failed_message_to_dlq",),
        "test_outbox_circuit_localstack": (
            "test_cb001_sqs_failures_open_breaker",
            "test_cb002_open_blocks_sends_without_claiming",
            "test_cb004_sqs_recovery_closes_after_probes",
            "test_cb005_finops_open_does_not_block_ota",
            "test_cb007_backlog_recovery_respects_rate_limit",
            "test_cb010_unknown_delivery_outcome_reconciled",
        ),
    },
}


def die(message: str) -> None:
    raise SystemExit(f"OUTBOX EVIDENCE REJECTED: {message}")


def read_bytes(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        die(f"missing or symlinked input: {path}")
    if not 0 < path.stat().st_size <= MAX_BYTES:
        die(f"invalid input size: {path}")
    return path.read_bytes()


def report_cases(path: Path) -> tuple[str, list[tuple[str, str, str]]]:
    data = read_bytes(path)
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        die(f"XML entity/DOCTYPE not permitted: {path}")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        die(f"invalid JUnit: {path}: {exc}")
    if root.tag not in {"testsuite", "testsuites"}:
        die(f"unexpected JUnit root: {root.tag}")
    cases: list[tuple[str, str, str]] = []
    for case in root.iter("testcase"):
        module = (case.get("classname") or "").rsplit(".", 1)[-1]
        name = case.get("name") or ""
        if not module.startswith("test_") or not name.startswith("test_"):
            die(f"missing test identity: {path}")
        status = "passed"
        for bad in ("failure", "error", "skipped"):
            if case.find(bad) is not None:
                status = bad
                break
        cases.append((module, name, status))
        if len(cases) > MAX_CASES:
            die(f"too many tests in {path}")
    if not cases:
        die(f"zero tests: {path}")
    if len(cases) != len(set((m, n) for m, n, _ in cases)):
        # Different pytest parameterizations retain their unique full names.
        die(f"duplicate test identities: {path}")
    bad_cases = [f"{m}.{n}({status})" for m, n, status in cases if status != "passed"]
    if bad_cases:
        die(f"failed, errored or skipped cases: {bad_cases[:8]}")
    return hashlib.sha256(data).hexdigest(), cases


def check_required(suite: str, cases: list[tuple[str, str, str]]) -> None:
    found = {(m, n.split("[", 1)[0]) for m, n, _ in cases}
    missing = [
        (module, name)
        for module, names in REQUIRED[suite].items()
        for name in names
        if (module, name) not in found
    ]
    if missing:
        die(f"missing mandatory {suite} cases: {missing}")


def validate_cost_report(path: Path) -> str:
    """Fail closed on absent or self-inconsistent real benchmark measurements."""
    raw = read_bytes(path)
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        die(f"invalid cost benchmark report: {exc}")
    if not isinstance(report, dict):
        die("cost benchmark must be a JSON object")
    if (
        report.get("schema") != "outbox-cost-benchmark-v1"
        or report.get("environment") != "github-hosted-postgres17-redis-localstack"
        or report.get("method") != "single-worker-sequential-real-sqs"
    ):
        die("cost benchmark identity or schema mismatched")
    count = report.get("event_count_per_batch")
    if type(count) is not int or not 100 <= count <= 1000:
        die("cost benchmark event count outside required window")
    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 4:
        die("cost benchmark must contain four batch measurements")
    for run, size in zip(runs, (1, 5, 10, 20), strict=True):
        if not isinstance(run, dict) or run.get("batch_size") != size:
            die(f"missing or unordered cost benchmark batch size: {size}")
        claims = (count + size - 1) // size
        exact = {
            "event_count": count,
            "published": count,
            "claim_transactions": claims,
            "published_transactions": count,
            "redis_eval_calls": claims + count,
            "sqs_send_calls": count,
            "sqs_unique_received": count,
        }
        for key, expected in exact.items():
            if type(run.get(key)) is not int or run[key] != expected:
                die(f"invalid measured {key} for batch {size}")
        for key in (
            "elapsed_ms",
            "process_cpu_ms",
            "throughput_events_per_sec",
            "sqs_send_mean_ms",
            "sqs_send_p95_ms",
        ):
            value = run.get(key)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                die(f"invalid cost metric {key} for batch {size}")
    return hashlib.sha256(raw).hexdigest()


def require_env(name: str, pattern: str) -> str:
    value = os.environ.get(name, "")
    if not re.fullmatch(pattern, value):
        die(f"invalid or missing {name}")
    return value


def source_identity() -> dict[str, str]:
    return {
        "repository": require_env("GITHUB_REPOSITORY", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
        "tested_sha": require_env("GITHUB_SHA", r"[a-f0-9]{40}"),
        "run_id": require_env("GITHUB_RUN_ID", r"[0-9]+"),
        "run_attempt": require_env("GITHUB_RUN_ATTEMPT", r"[0-9]+"),
        "event": require_env(
            "GITHUB_EVENT_NAME", r"(pull_request|push|merge_group|workflow_dispatch)"
        ),
    }


def generate(args: argparse.Namespace) -> None:
    identity = source_identity()
    workflow = os.environ.get("GITHUB_WORKFLOW")
    if workflow != WORKFLOW:
        die(f"unexpected GITHUB_WORKFLOW: {workflow}")
    try:
        checkout_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        die("git checkout cannot be identified")
    if checkout_sha != identity["tested_sha"]:
        die("checkout SHA differs from tested SHA")
    path = Path(args.junit)
    digest, cases = report_cases(path)
    check_required(args.suite, cases)
    benchmark_sha256 = (
        validate_cost_report(Path(args.benchmark))
        if args.suite == "cost" and args.benchmark
        else None
    )
    if args.suite == "cost" and benchmark_sha256 is None:
        die("cost suite requires --benchmark report")

    payload = {
        "schema": SCHEMA,
        "workflow": WORKFLOW,
        "suite": args.suite,
        "source": identity,
        "junit_sha256": digest,
        "case_count": len(cases),
        "benchmark_sha256": benchmark_sha256,
        "cases": [{"module": m, "name": n, "status": status} for m, n, status in cases],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Generated {args.suite}: {len(cases)} passing cases, SHA256={digest}")


def verify(args: argparse.Namespace) -> None:
    expected = {
        "repository": require_env("EXPECTED_REPOSITORY", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
        "tested_sha": require_env("EXPECTED_SHA", r"[a-f0-9]{40}"),
        "run_id": require_env("EXPECTED_RUN_ID", r"[0-9]+"),
        "run_attempt": require_env("EXPECTED_RUN_ATTEMPT", r"[0-9]+"),
        "event": require_env(
            "EXPECTED_EVENT", r"(pull_request|push|merge_group|workflow_dispatch)"
        ),
    }
    base = Path(args.evidence_root)
    for suite in REQUIRED:
        folder = base / suite
        junit = folder / "results.xml"
        manifest = folder / "manifest.json"
        digest, cases = report_cases(junit)
        check_required(suite, cases)
        try:
            payload = json.loads(read_bytes(manifest))
        except (ValueError, UnicodeDecodeError) as exc:
            die(f"invalid manifest: {suite}: {exc}")
        if not isinstance(payload, dict) or (
            payload.get("schema") != SCHEMA
            or payload.get("workflow") != WORKFLOW
            or payload.get("suite") != suite
            or payload.get("source") != expected
            or payload.get("junit_sha256") != digest
            or payload.get("case_count") != len(cases)
        ):
            die(f"inconsistent manifest/provenance: {suite}")
        expected_cases = [{"module": m, "name": n, "status": status} for m, n, status in cases]
        if payload.get("cases") != expected_cases:
            die(f"tampered or inconsistent test list: {suite}")
        expected_benchmark = (
            validate_cost_report(folder / "benchmark.json") if suite == "cost" else None
        )
        if payload.get("benchmark_sha256") != expected_benchmark:
            die(f"tampered or missing benchmark data: {suite}")
        print(f"PASS {suite}: {len(cases)} verified cases, source={expected['tested_sha']}")
    print("OUTBOX ENTERPRISE EVIDENCE: ALL REQUIRED REPORTS VERIFIED")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    make = sub.add_parser("generate")
    make.add_argument("--suite", choices=tuple(REQUIRED), required=True)
    make.add_argument("--junit", required=True)
    make.add_argument("--benchmark")
    make.add_argument("--output", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--evidence-root", required=True)
    args = parser.parse_args()
    (generate if args.mode == "generate" else verify)(args)


if __name__ == "__main__":
    main()
