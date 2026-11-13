"""Verify the same-attempt rollout contract report."""

from __future__ import annotations

import json
import os
from pathlib import Path

from scripts.iac.day31_evidence import provenance, xml_cases
from scripts.iac.pipeline_evidence import verify

CASES = {
    "test_approval_binds_exact_release_and_stable_execution",
    "test_success_requires_all_waves_and_final_evidence",
    "test_ota_timeout_pauses_without_reverting_firmware",
    "test_ecs_rollback_failure_requires_intervention",
    "test_approval_unavailable_never_opens_wave",
    "test_day42_pause_replay_and_native_job_reconciliation",
}


def main() -> None:
    root = Path(".day42-input")
    proofs = verify(root, "day42-rollout")
    if set(proofs) != {"rollout.xml"}:
        raise ValueError("Unexpected rollout report inventory")
    xml_cases((root / "rollout.xml").read_bytes(), CASES, {}, exact=True)
    receipt = {
        "provenance": provenance(),
        "offline_decision": "VERIFIED",
        "staging_decision": "BLOCKED",
        "production_authorized": False,
        "proofs_sha256": proofs,
    }
    Path("day42-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write("**Day42 offline:** VERIFIED\n\n**AWS Staging:** BLOCKED\n")


if __name__ == "__main__":
    main()
