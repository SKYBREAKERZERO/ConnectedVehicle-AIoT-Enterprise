"""Outbox CI evidence verifier. Stdlib-only: safe for an isolated gate runner.

This verifies provenance *claims* and report integrity. Trust in the tests themselves
requires protected, reviewed workflow/test code and a separate trusted workflow_run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

SCHEMA = "outbox-ci-evidence-v1"
WORKFLOW = "Outbox Dispatcher Enterprise Runtime"
MAX_BYTES = 10 * 1024 * 1024
MAX_CASES = 10_000

# Each case must appear in the named pytest module, not just anywhere in a report.
REQUIRED = {
    "contract": {
        "test_reliability_retry": (
            "test_retry_delay_applies_symmetric_jitter",
            "test_retry_raises_after_attempts_exhausted",
        ),
        "test_outbox_dispatcher": (
            "test_dispatcher_persists_retry_with_exponential_backoff",
            "test_retry_exhaustion_is_fenced_and_persisted",
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
        "test_database_runtime_permissions": (
            "test_real_postgres_runtime_permissions",
        ),
        "test_outbox_circuit_pg": (
            "test_cb003_half_open_single_probe_across_workers",
            "test_cb006_restart_restores_open_state",
            "test_cb008_open_preserves_attempts_and_schedule",
            "test_cb009_runtime_role_isolation_pg17",
        ),
    },
    "delivery": {
        "test_localstack_sqs_dlq": (
            "test_localstack_sqs_redrives_failed_message_to_dlq",
        ),
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
        name = (case.get("name") or "")
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
    missing = [(module, name) for module, names in REQUIRED[suite].items()
               for name in names if (module, name) not in found]
    if missing:
        die(f"missing mandatory {suite} cases: {missing}")


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
        "event": require_env("GITHUB_EVENT_NAME", r"(pull_request|push|merge_group|workflow_dispatch)"),
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
    payload = {
        "schema": SCHEMA,
        "workflow": WORKFLOW,
        "suite": args.suite,
        "source": identity,
        "junit_sha256": digest,
        "case_count": len(cases),
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
        "event": require_env("EXPECTED_EVENT", r"(pull_request|push|merge_group|workflow_dispatch)"),
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
            payload.get("schema") != SCHEMA or
            payload.get("workflow") != WORKFLOW or
            payload.get("suite") != suite or
            payload.get("source") != expected or
            payload.get("junit_sha256") != digest or
            payload.get("case_count") != len(cases)
        ):
            die(f"inconsistent manifest/provenance: {suite}")
        expected_cases = [{"module": m, "name": n, "status": status}
                          for m, n, status in cases]
        if payload.get("cases") != expected_cases:
            die(f"tampered or inconsistent test list: {suite}")
        print(f"PASS {suite}: {len(cases)} verified cases, source={expected['tested_sha']}")
    print("OUTBOX ENTERPRISE EVIDENCE: ALL REQUIRED REPORTS VERIFIED")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    make = sub.add_parser("generate")
    make.add_argument("--suite", choices=tuple(REQUIRED), required=True)
    make.add_argument("--junit", required=True)
    make.add_argument("--output", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--evidence-root", required=True)
    args = parser.parse_args()
    (generate if args.mode == "generate" else verify)(args)


if __name__ == "__main__":
    main()