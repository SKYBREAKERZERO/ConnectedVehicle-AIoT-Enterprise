"""Readiness evidence and opt-in exact-head GitHub gate. Never deploys or merges."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from database.credential_journal import strict_json
from enterprise_platform.reliability.slo import CanaryReport, evaluate_window
from scripts import day16_evidence
from scripts.day17_rules import POLICY, RULES, generated, policy

ROOT = Path(__file__).resolve().parents[1]
REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
OTA_CHECKS = frozenset(
    {
        "inventory_registration_idempotent",
        "negative_requests_no_side_effects",
        "release_immutable_and_idempotent",
        "cross_tenant_api_denied",
        "authentication_and_ota_permission_required",
        "hardware_mismatch_rejected",
        "concurrent_duplicate_single_job",
        "one_outstanding_job_per_ecu",
        "job_idempotency_conflicts_rejected",
        "job_query_persisted",
        "audit_failure_rolls_back_create_and_cancel",
        "cancellation_idempotent_and_audited",
        "fixed_login_rls_blocks_forged_context",
        "workers_denied_all_ota_tables",
        "runtime_ddl_and_immutable_updates_denied",
        "audit_actor_time_and_single_operation",
        "runtime_security_contract_verified",
        "competing_operations_single_active_job",
        "composite_foreign_keys_enforce_ownership_and_hardware",
        "rls_force_drift_rejected",
    }
)


def readiness_digest() -> str:
    digest = hashlib.sha256(day16_evidence.source_digest().encode())
    for relative in (
        "config/operations/day17-slo.json",
        "infra/observability/day17-slo.yml",
        "infra/observability/local-prometheus.yml",
        "infra/observability/compose.yml",
        "tests/fixtures/day17/alerts.test.yml",
        "docs/DAY17_OPERATIONS.md",
        "docs/DAY17_OTA_FOUNDATION.md",
        "contracts/platform-v1.json",
        ".github/workflows/runtime.yml",
    ):
        digest.update(relative.encode() + b"\0")
        digest.update((ROOT / relative).read_text(encoding="utf-8").encode())
    sql_files = [
        *(ROOT / "database").glob("*.sql"),
        *(ROOT / "database/migrations/sql").glob("*.sql"),
    ]
    for path in sorted(sql_files):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_text(encoding="utf-8").encode())
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Oversized operational evidence")
    record = strict_json(data.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError("Evidence must be an object")
    return record


def write_json(path: Path, record: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def policy_digest() -> str:
    return hashlib.sha256(POLICY.read_text(encoding="utf-8").encode()).hexdigest()


def verify_day16(directory: Path, provenance: dict[str, str], *, now: datetime) -> dict[str, Any]:
    manifest = read_json(directory / "day16-acceptance.json")
    if (
        manifest.get("status") != "passed"
        or manifest.get("provenance") != provenance
        or manifest.get("real_aws_verified") is not False
    ):
        raise ValueError("Day16 acceptance belongs to another run/source")
    expected = []
    for name in sorted(day16_evidence.SCENARIOS):
        path = directory / ("day16-" + name + ".json")
        row = read_json(path)
        stamp = datetime.fromisoformat(row["generated_at_utc"])
        if (
            stamp.utcoffset() is None
            or not -5 <= (now - stamp).total_seconds() <= policy().maximum_evidence_age_seconds
        ):
            raise ValueError("Prerequisite evidence expired")
        if (
            row.get("provenance") != provenance
            or row.get("scenario") != name
            or set(row.get("checks", {})) != day16_evidence.REQUIRED[name]
            or any(value is not True for value in row["checks"].values())
            or row.get("real_aws_verified") is not False
        ):
            raise ValueError("Invalid prerequisite fault evidence")
        expected.append({"scenario": name, "sha256": digest(path)})
    proof_path = directory / "day16-demo-proof.json"
    proof = read_json(proof_path)
    if (
        manifest.get("records") != expected
        or manifest.get("demo_proof_sha256") != digest(proof_path)
        or proof.get("provenance") != provenance
    ):
        raise ValueError("Prerequisite evidence changed")
    day16_evidence.validate_demo(proof)
    return proof


def evaluate(directory: Path, *, now: datetime | None = None) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    if RULES.read_text(encoding="utf-8") != generated():
        raise ValueError("SLO policy/rule drift")
    report = CanaryReport.model_validate_json(
        json.dumps(read_json(directory / "day17-canary.json"))
    )
    if (
        report.provenance.get("source_sha256") != day16_evidence.source_digest()
        or report.readiness_sha256 != readiness_digest()
    ):
        raise ValueError("Readiness evidence is stale for this source/policy")
    proof = verify_day16(directory, report.provenance, now=current)
    ota = read_json(directory / "day17-ota-foundation.json")
    observed = datetime.fromisoformat(ota["generated_at_utc"])
    if (
        ota.get("version") != 1
        or ota.get("profile") != "local_drill"
        or ota.get("provenance") != report.provenance
        or ota.get("real_aws_verified") is not False
        or ota.get("device_execution_verified") is not False
        or set(ota.get("checks", {})) != OTA_CHECKS
        or any(value is not True for value in ota["checks"].values())
        or observed.utcoffset() is None
        or not -5 <= (current - observed).total_seconds() <= policy().maximum_evidence_age_seconds
    ):
        raise ValueError("Missing, inconsistent or expired OTA foundation evidence")
    target = policy()
    fault = evaluate_window(report.fault, target, now=current)
    recovered = evaluate_window(report.recovered, target, now=current)
    recovery = {row["case"]: row["elapsed_seconds"] for row in proof["cases"]}
    checks = {
        "fault_caused_abort": fault["decision"] == "abort"
        and fault["failures"] >= 5
        and not fault["checks"]["availability"],
        "recovered_canary": recovered["decision"] == "proceed",
        "recovery_objective": all(
            0 < value <= target.recovery_seconds for value in recovery.values()
        ),
        "ota_foundation": True,
    }
    files = [
        "day16-acceptance.json",
        "day16-demo-proof.json",
        "day17-canary.json",
        "day17-ota-foundation.json",
    ]
    return {
        "version": 1,
        "profile": "local_drill",
        "decision": "ready_for_local_release" if all(checks.values()) else "abort",
        "provenance": report.provenance,
        "readiness_sha256": report.readiness_sha256,
        "checks": checks,
        "fault_window": fault,
        "recovered_window": recovered,
        "recovery_seconds": recovery,
        "bundle_sha256": {name: digest(directory / name) for name in files},
        "policy_sha256": policy_digest(),
        "real_aws_verified": False,
    }


def verify_readiness(directory: Path) -> dict[str, Any]:
    recorded = read_json(directory / "day17-readiness.json")
    actual = evaluate(directory)
    if recorded != actual or actual["decision"] != "ready_for_local_release":
        raise ValueError("Release readiness rejected, changed or expired")
    return actual


def github_gate(
    head: str,
    merge: str,
    metadata: dict[str, Any],
    protection: dict[str, Any],
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    if (
        re.fullmatch(r"[0-9a-f]{40}", head) is None
        or metadata.get("head", {}).get("sha") != head
        or merge not in {head, metadata.get("merge_commit_sha")}
    ):
        raise ValueError("Release is not bound to the current PR head/merge result")
    status = protection.get("required_status_checks") or {}
    trusted = {(row["context"], row.get("app_id")) for row in status.get("checks", [])}
    if (
        not status.get("strict")
        or not (protection.get("enforce_admins") or {}).get("enabled")
        or not {("Runtime quality gate", 15368), ("IaC quality gate", 15368)} <= trusted
    ):
        raise ValueError("Required trusted checks are not enforced")
    selected = {}
    attempts = {}
    for name, path in (
        ("Runtime quality gates", ".github/workflows/runtime.yml"),
        ("IaC quality gates", ".github/workflows/ci.yml"),
    ):
        matches = [
            run
            for run in runs
            if run.get("name") == name
            and run.get("head_sha") == head
            and run.get("event") == "pull_request"
            and run.get("path") == path
        ]
        if not matches:
            raise ValueError("Missing exact-head workflow")
        latest = max(matches, key=lambda run: (run["id"], run.get("run_attempt", 1)))
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            raise ValueError("Latest workflow has not passed")
        selected[name] = latest["id"]
        attempts[name] = latest.get("run_attempt", 1)
    return {
        "head": head,
        "evidence_commit": merge,
        "runs": selected,
        "attempts": attempts,
        "trusted_checks_enforced": True,
    }


def gh(endpoint: str) -> dict[str, Any]:
    return read_response(subprocess.check_output(["gh", "api", endpoint], text=True, timeout=30))


def verify_artifact(
    archive: bytes,
    metadata: dict[str, Any],
    expected: dict[str, bytes],
    *,
    head: str,
    run_id: int,
) -> dict[str, Any]:
    """Bind evidence bytes to the authenticated Actions artifact, without extracting files."""
    checksum = "sha256:" + hashlib.sha256(archive).hexdigest()
    if (
        metadata.get("expired") is not False
        or metadata.get("digest") != checksum
        or metadata.get("workflow_run", {}).get("id") != run_id
        or metadata.get("workflow_run", {}).get("head_sha") != head
        or len(archive) > 50 * 1024 * 1024
    ):
        raise ValueError("Untrusted, expired or mismatched Actions artifact")
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        names = package.namelist()
        if len(names) != len(set(names)) or not expected.keys() <= set(names):
            raise ValueError("Missing or ambiguous artifact evidence")
        for name, value in expected.items():
            if package.getinfo(name).file_size > 1024 * 1024 or package.read(name) != value:
                raise ValueError("Local evidence differs from uploaded Actions evidence")
    return {"id": metadata["id"], "name": metadata["name"], "digest": checksum}


def verify_remote_artifacts(directory: Path, head: str, run_id: int) -> list[dict[str, Any]]:
    records = gh(f"repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    result = []
    groups = {
        "day16-local-resilience": [
            "day16-acceptance.json",
            "day16-demo-proof.json",
            *("day16-" + name + ".json" for name in sorted(day16_evidence.SCENARIOS)),
        ],
        "day17-local-readiness": [
            "day17-canary.json",
            "day17-readiness.json",
            "day17-ota-foundation.json",
        ],
    }
    for name, filenames in groups.items():
        matches = [row for row in records if row.get("name") == name]
        if not matches:
            raise ValueError("Missing uploaded Actions artifact: " + name)
        metadata = max(matches, key=lambda row: row["id"])
        archive = subprocess.check_output(
            ["gh", "api", f"repos/{REPO}/actions/artifacts/{metadata['id']}/zip"], timeout=60
        )
        result.append(
            verify_artifact(
                archive,
                metadata,
                {filename: (directory / filename).read_bytes() for filename in filenames},
                head=head,
                run_id=run_id,
            )
        )
    return result


def read_response(value: str) -> dict[str, Any]:
    row = strict_json(value)
    if not isinstance(row, dict):
        raise ValueError("Invalid GitHub response")
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    parser.add_argument("--check-existing", action="store_true")
    parser.add_argument(
        "--require-remote",
        type=int,
        metavar="PR",
        help="Read-only GitHub validation; does not merge",
    )
    args = parser.parse_args()
    if args.require_remote:
        local = verify_readiness(args.directory)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        metadata = gh(f"repos/{REPO}/pulls/{args.require_remote}")
        if (
            metadata.get("base", {}).get("ref") != "main"
            or metadata.get("head", {}).get("repo", {}).get("full_name", "").lower() != REPO.lower()
        ):
            raise ValueError("Unexpected release repository/base")
        gate = github_gate(
            head,
            local["provenance"]["commit"],
            metadata,
            gh(f"repos/{REPO}/branches/main/protection"),
            gh(f"repos/{REPO}/actions/runs?head_sha={head}&per_page=100")["workflow_runs"],
        )
        expected_run = (
            str(gate["runs"]["Runtime quality gates"])
            + ":"
            + str(gate["attempts"]["Runtime quality gates"])
        )
        if local["provenance"].get("run_id") != expected_run:
            raise ValueError("Evidence is not from the latest successful Runtime attempt")
        artifacts = verify_remote_artifacts(
            args.directory, head, gate["runs"]["Runtime quality gates"]
        )
        # Downloads must not silently extend the evidence freshness deadline.
        verify_readiness(args.directory)
        print(
            write_json(
                args.directory / "day17-remote-release.json",
                dict(
                    gate,
                    artifacts=artifacts,
                    decision="ready_for_review",
                    real_aws_verified=False,
                    merged=False,
                ),
            )
        )
    elif args.check_existing:
        verify_readiness(args.directory)
        print("Day17 readiness and SLO proof verified")
    else:
        report = evaluate(args.directory)
        path = write_json(args.directory / "day17-readiness.json", report)
        if report["decision"] != "ready_for_local_release":
            raise ValueError("Release gate aborted; inspect " + str(path))
        print(path)


if __name__ == "__main__":
    main()
