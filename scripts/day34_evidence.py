"""Exact-source Day34 local-drill evidence. Never authorizes a production release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day16_evidence import ROOT, provenance
from scripts.day18_evidence import REQUIRED as EXECUTION_CHECKS
from scripts.day19_evidence import REQUIRED as CAMPAIGN_CHECKS
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.pipeline_evidence import require_needs

POSTGRES_CASES = {
    "test_runtime_authority_and_unique_migration_head",
    "test_two_dispatchers_same_wave_and_replay_create_one_job",
    "test_process_crash_after_job_commit_can_replay",
    "test_skip_locked_allocates_disjoint_campaigns",
    "test_connection_death_rolls_back_uncommitted_claim",
    "test_process_crash_after_claim_recovers_and_fences_old_owner",
    "test_commit_then_http_response_loss_is_idempotent",
    "test_pause_serializes_before_waiting_tick",
    "test_pause_and_cancel_preserve_previously_claimed_jobs",
    "test_lock_timeout_retries_are_bounded_and_do_not_pause",
    "test_real_deadlock_rolls_back_and_retries_whole_transaction",
    "test_real_serialization_failure_retries_fresh_transaction[False]",
    "test_real_serialization_failure_retries_fresh_transaction[True]",
}
COMMANDS = {
    "ruff": ["-m", "ruff", "check", "."],
    "format": ["-m", "ruff", "format", "--check", "."],
    "mypy": ["-m", "mypy", "."],
    "contracts": ["-m", "scripts.contracts", "--require-day17", "--require-day18"],
    "heads": ["-m", "alembic", "heads"],
    "pytest": ["-m", "pytest", "tests/unit", "tests/contract", "-q"],
}


def binding() -> dict[str, str]:
    result = provenance()
    digest = hashlib.sha256(result["source_sha256"].encode())
    for name in ("pyproject.toml", "alembic.ini"):
        digest.update((ROOT / name).read_bytes())
    for directory in (".github", "contracts", "database/migrations"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
                digest.update(path.read_bytes())
    result["day34_source_sha256"] = digest.hexdigest()
    return result


def write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def quality(directory: Path) -> bool:
    before = binding()
    results = {}
    for name, arguments in COMMANDS.items():
        result = subprocess.run(
            [sys.executable, *arguments], cwd=ROOT, capture_output=True, timeout=900
        )
        log = result.stdout + result.stderr
        (directory / f"day34-{name}.log").write_bytes(log)
        results[name] = {
            "exit_code": result.returncode,
            "log_sha256": hashlib.sha256(log).hexdigest(),
        }
        print(f"{name}: {result.returncode}", flush=True)
        if name == "heads" and result.stdout.decode().strip() != "b16f238d45ac (head)":
            results[name]["exit_code"] = 1
    if before != binding():
        raise ValueError("Source changed while quality checks were executing")
    write(
        directory / "day34-quality.json",
        {
            "provenance": before,
            "checks": results,
            "generated_at_utc": datetime.now(UTC).isoformat(),
        },
    )
    return all(r["exit_code"] == 0 for r in results.values())


def fresh(record: dict[str, Any]) -> None:
    stamp = datetime.fromisoformat(record["generated_at_utc"])
    if stamp.utcoffset() is None or not -5 <= (datetime.now(UTC) - stamp).total_seconds() <= 3600:
        raise ValueError("Evidence is stale or has an invalid timestamp")


def evaluate(directory: Path) -> dict[str, Any]:
    expected = binding()
    ci_results = os.environ.get("PIPELINE_NEEDS")
    if os.environ.get("GITHUB_ACTIONS") == "true" and not ci_results:
        raise ValueError("Native CI upstream results are missing")
    if ci_results:
        require_needs(
            {"baseline", "lint", "types", "contracts", "integration", "postgres", "observability"},
            json.loads(ci_results),
        )
    proofs: dict[str, str] = {}
    for name, required in (
        ("day18-ota-execution.json", EXECUTION_CHECKS),
        ("day19-campaign.json", CAMPAIGN_CHECKS),
    ):
        raw = (directory / name).read_bytes()
        record = json.loads(raw)
        fresh(record)
        if (
            record.get("provenance") != provenance()
            or record.get("version") != 1
            or record.get("profile") != "local_drill"
            or set(record.get("checks", {})) != required
            or any(value is not True for value in record["checks"].values())
            or record.get("simulated_installation") is not True
            or record.get("physical_boot_verified") is not False
            or record.get("real_aws_verified") is not False
        ):
            raise ValueError(f"Missing/failed/mixed-source runtime proof: {name}")
        proofs[name] = hashlib.sha256(raw).hexdigest()
    name = "day21-postgres.xml"
    raw = (directory / name).read_bytes()
    xml_cases(raw, POSTGRES_CASES, expected)
    proofs[name] = hashlib.sha256(raw).hexdigest()
    name = "day34-quality.json"
    raw = (directory / name).read_bytes()
    record = json.loads(raw)
    fresh(record)
    if record.get("provenance") != expected or set(record.get("checks", {})) != set(COMMANDS):
        raise ValueError("Quality checks missing or from another source/run")
    for check, result in record["checks"].items():
        log = (directory / f"day34-{check}.log").read_bytes()
        if type(result.get("exit_code")) is not int or result["exit_code"] != 0:
            raise ValueError(f"Quality check failed: {check}")
        if hashlib.sha256(log).hexdigest() != result.get("log_sha256"):
            raise ValueError(f"Quality log altered: {check}")
    proofs[name] = hashlib.sha256(raw).hexdigest()
    return {
        "version": 1,
        "decision": "READY_FOR_LOCAL_REVIEW",
        "provenance": expected,
        "proofs": proofs,
        "release_authorized": False,
        "real_aws_verified": False,
        "physical_boot_verified": False,
        "simulated_installation": True,
        "ci_verified": bool(ci_results),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.getenv("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    parser.add_argument("--quality", action="store_true")
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.quality:
        return 0 if quality(args.directory) else 1
    try:
        result = evaluate(args.directory)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"decision": "BLOCKED", "release_authorized": False, "reason": str(exc)}
    write(args.directory / "day34-acceptance.json", result)
    print(json.dumps(result, indent=2))
    return 1 if result["decision"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
