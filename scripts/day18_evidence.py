"""Fresh local OTA evidence, source binding and optional authenticated CI artifact checks."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day17_release import (
    REPO,
    ROOT,
    gh,
    read_json,
    readiness_digest,
    verify_artifact,
    verify_readiness,
    write_json,
)
from scripts.day17_rules import policy

REQUIRED = frozenset(
    {
        "independent_ecu_proof_and_replay_protection",
        "database_credential_cannot_forge_installation",
        "database_authority_drift_fails_closed",
        "unverified_claim_denied",
        "untrusted_signature_denied",
        "checksum_failure_no_execution_side_effects",
        "concurrent_verification_single_transition",
        "v1_contract_rejects_opted_in_v2_state",
        "tenant_vehicle_and_principal_authorization",
        "ordered_reports_and_stale_claim_fenced",
        "download_crash_recovered",
        "activation_and_terminal_outbox_atomic",
        "authentication_failure_retains_pending_report",
        "regressed_report_time_denied",
        "audit_failure_rolls_back_installation_report",
        "lost_terminal_response_reconciled_idempotently",
        "process_restart_single_activation",
        "pinned_historical_object_installed",
        "conflicting_terminal_event_rejected",
        "cloud_monotonic_security_version",
        "health_failure_preserves_previous_bank",
        "active_image_corruption_fails_closed",
        "cloud_inventory_reports_and_audit_agree",
        "database_monotonic_counter_guard",
        "device_discovers_verified_job",
    }
)


def source_digest() -> str:
    return hashlib.sha256(
        (
            readiness_digest() + (ROOT / "docs/DAY18_OTA_EXECUTION.md").read_text(encoding="utf-8")
        ).encode()
    ).hexdigest()


def evaluate(directory: Path) -> dict[str, Any]:
    base = verify_readiness(directory)
    proof = read_json(directory / "day18-ota-execution.json")
    observed = datetime.fromisoformat(proof["generated_at_utc"])
    if (
        proof.get("provenance") != base["provenance"]
        or proof.get("day18_sha256") != source_digest()
        or proof.get("version") != 1
        or proof.get("profile") != "local_drill"
        or proof.get("real_aws_verified") is not False
        or proof.get("simulated_installation") is not True
        or set(proof.get("checks", {})) != REQUIRED
        or any(value is not True for value in proof["checks"].values())
        or observed.utcoffset() is None
        or not -5
        <= (datetime.now(UTC) - observed).total_seconds()
        <= policy().maximum_evidence_age_seconds
        or any(
            type(proof.get(name)) is not int or proof[name] != expected
            for name, expected in {
                "device_installations": 1,
                "cloud_security_version": 1,
                "device_security_version": 1,
                "pending_reports": 0,
            }.items()
        )
    ):
        raise ValueError("Day18 evidence missing, inconsistent, stale or from another source")
    return dict(
        version=1,
        decision="ready_for_local_review",
        profile="local_drill",
        provenance=base["provenance"],
        day18_sha256=source_digest(),
        proofs={
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("day17-readiness.json", "day18-ota-execution.json")
        },
        real_aws_verified=False,
        simulated_installation=True,
    )


def verify(directory: Path) -> dict[str, Any]:
    actual = evaluate(directory)
    if read_json(directory / "day18-acceptance.json") != actual:
        raise ValueError("Day18 acceptance changed")
    return actual


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.environ.get("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    parser.add_argument("--check-existing", action="store_true")
    parser.add_argument("--require-remote", type=int, metavar="PR")
    args = parser.parse_args()
    if args.require_remote:
        verify(args.directory)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.day17_release",
                "--directory",
                str(args.directory),
                "--require-remote",
                str(args.require_remote),
            ],
            cwd=ROOT,
            check=True,
            timeout=90,
        )
        remote = read_json(args.directory / "day17-remote-release.json")
        run = remote["runs"]["Runtime quality gates"]
        records = gh(f"repos/{REPO}/actions/runs/{run}/artifacts?per_page=100")["artifacts"]
        matches = [row for row in records if row.get("name") == "day18-local-execution"]
        if not matches:
            raise ValueError("Missing Day18 uploaded artifact")
        metadata = max(matches, key=lambda row: row["id"])
        archive = subprocess.check_output(
            ["gh", "api", f"repos/{REPO}/actions/artifacts/{metadata['id']}/zip"], timeout=60
        )
        artifact = verify_artifact(
            archive,
            metadata,
            {
                name: (args.directory / name).read_bytes()
                for name in ("day18-ota-execution.json", "day18-acceptance.json")
            },
            head=remote["head"],
            run_id=run,
        )
        verify(args.directory)
        remote["artifacts"].append(artifact)
        remote["simulated_installation"] = True
        print(write_json(args.directory / "day18-remote-release.json", remote))
    elif args.check_existing:
        verify(args.directory)
        print("Day18 signed execution, durable state and source evidence verified")
    else:
        print(write_json(args.directory / "day18-acceptance.json", evaluate(args.directory)))


if __name__ == "__main__":
    main()
