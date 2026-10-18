"""Fresh, immutable campaign acceptance chained to Day18 and exact-head GitHub artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day17_release import REPO, ROOT, gh, read_json, verify_artifact, write_json
from scripts.day17_rules import policy
from scripts.day18_evidence import source_digest as day18_digest
from scripts.day18_evidence import verify as verify_day18

BASELINE = "d336c8a1be301ea08c79374c173ce0a4c8ef4f13"
REQUIRED = frozenset(
    {
        "wave_job_audit_failure_rolls_back_all_effects",
        "shared_login_cannot_select_campaign_tenant",
        "observation_window_blocks_early_promotion",
        "graceful_shutdown_stops_dispatch_and_closes_pool",
        "stalled_wave_times_out_without_inventing_success",
        "create_freeze_idempotent_conflicts_rejected",
        "immutable_target_snapshot_and_wave_assignment",
        "fixed_login_rls_and_runtime_writes_denied",
        "dispatcher_crash_concurrency_single_job_per_target",
        "canary_success_releases_wave_and_real_devices_complete",
        "inventory_reports_audit_and_snapshot_agree",
        "audit_failure_rolls_back_snapshot_and_retry_is_safe",
        "failed_canary_blocks_later_waves_and_resume",
        "inactive_vehicle_pauses_and_inflight_result_can_reconcile",
        "competing_campaigns_cannot_duplicate_active_ecu_jobs",
        "cancellation_withdraws_unclaimed_jobs_without_faking_execution",
        "publisher_revocation_blocks_dispatch_with_stale_registry",
        "snapshot_and_canary_policy_cannot_be_bypassed_by_db_credentials",
    }
)


def source_digest() -> str:
    return hashlib.sha256(
        (
            BASELINE
            + day18_digest()
            + (ROOT / "docs/DAY19_CAMPAIGNS.md").read_text(encoding="utf-8")
        ).encode()
    ).hexdigest()


def evaluate(directory: Path) -> dict[str, Any]:
    prerequisite = verify_day18(directory)
    proof = read_json(directory / "day19-campaign.json")
    stamp = datetime.fromisoformat(proof["generated_at_utc"])
    if (
        proof.get("provenance") != prerequisite["provenance"]
        or proof.get("version") != 1
        or proof.get("profile") != "local_drill"
        or proof.get("day19_sha256") != source_digest()
        or proof.get("real_aws_verified") is not False
        or proof.get("physical_boot_verified") is not False
        or proof.get("simulated_installation") is not True
        or type(proof.get("device_successes")) is not int
        or proof["device_successes"] != 4
        or set(proof.get("checks", {})) != REQUIRED
        or any(value is not True for value in proof["checks"].values())
        or stamp.utcoffset() is None
        or not -5
        <= (datetime.now(UTC) - stamp).total_seconds()
        <= policy().maximum_evidence_age_seconds
    ):
        raise ValueError("Campaign evidence missing, altered, stale or from another source/run")
    subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE, "HEAD"], cwd=ROOT, check=True)
    return dict(
        version=1,
        decision="ready_for_local_review",
        profile="local_drill",
        baseline=BASELINE,
        provenance=prerequisite["provenance"],
        day19_sha256=source_digest(),
        proofs={
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("day18-acceptance.json", "day19-campaign.json")
        },
        real_aws_verified=False,
        physical_boot_verified=False,
        simulated_installation=True,
    )


def verify(directory: Path) -> dict[str, Any]:
    actual = evaluate(directory)
    if read_json(directory / "day19-acceptance.json") != actual:
        raise ValueError("Campaign acceptance changed")
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
                "scripts.day18_evidence",
                "--directory",
                str(args.directory),
                "--require-remote",
                str(args.require_remote),
            ],
            cwd=ROOT,
            check=True,
            timeout=120,
        )
        remote = read_json(args.directory / "day18-remote-release.json")
        run = remote["runs"]["Runtime quality gates"]
        rows = gh(f"repos/{REPO}/actions/runs/{run}/artifacts?per_page=100")["artifacts"]
        record = max(
            (row for row in rows if row["name"] == "day19-local-campaign"), key=lambda r: r["id"]
        )
        archive = subprocess.check_output(
            ["gh", "api", f"repos/{REPO}/actions/artifacts/{record['id']}/zip"], timeout=60
        )
        artifact = verify_artifact(
            archive,
            record,
            {
                name: (args.directory / name).read_bytes()
                for name in ("day19-campaign.json", "day19-acceptance.json")
            },
            head=remote["head"],
            run_id=run,
        )
        verify(args.directory)
        remote["artifacts"].append(artifact)
        remote["day19_baseline"] = BASELINE
        print(write_json(args.directory / "day19-remote-release.json", remote))
    elif args.check_existing:
        verify(args.directory)
        print("Day19 frozen targets, rollout gates and recovery evidence verified")
    else:
        print(write_json(args.directory / "day19-acceptance.json", evaluate(args.directory)))


if __name__ == "__main__":
    main()
