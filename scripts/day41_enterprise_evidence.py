"""Build the Day41 enterprise receipt from verified same-attempt artifacts."""

from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from pathlib import Path

from scripts.day40_runtime_evidence import REPORTS, identity
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.pipeline_evidence import verify

CASES = {
    "rotation": {
        "test_verified_sequence_allows_a_later_operation[postgres]",
        "test_verified_sequence_allows_a_later_operation[redis]",
        "test_interruption_is_persistent_and_blocks_other_credential",
        "test_retirement_cannot_skip_client_replacement",
        "test_unknown_acknowledgement_allows_only_exact_observation_replay",
        "test_sqlite_serializes_competing_credentials",
    },
    "admission": {
        "test_pr_or_other_sha_cannot_replace_main_proof",
        "test_latest_attempt_cannot_fall_back[failure]",
        "test_latest_attempt_cannot_fall_back[cancelled]",
        "test_latest_attempt_cannot_fall_back[None]",
        "test_missing_skipped_or_foreign_job_blocks",
        "test_pr_cannot_execute_trusted_source",
    },
}


def main() -> None:
    root = Path(".day41")
    facts = identity()
    run_id = facts["day31_run_id"]
    if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", run_id):
        raise ValueError("Day41 requires a GitHub run and attempt")
    raw_decision = (root / "runtime/decision.json").read_bytes()
    decision = json.loads(raw_decision)
    sealed = verify(root / "aggregate", "aggregate")
    aggregate = json.loads((root / "aggregate/aggregate.json").read_bytes())
    if (
        decision["provenance"] != facts
        or aggregate["provenance"] != facts
        or sealed != {"aggregate.json": decision["aggregate_sha256"]}
        or set(aggregate["reports"]) != set(REPORTS)
        or decision["local_decision"] != "ROTATION_TESTED_LOCAL"
        or decision["aws_staging_decision"] != "BLOCKED"
        or any(
            decision[key] is not False
            for key in ("aws_rotation_verified", "release_authorized", "production_authorized")
        )
    ):
        raise ValueError("Runtime provenance, evidence or authorization mismatch")
    proofs = {"runtime_decision": sha256(raw_decision).hexdigest(), **sealed}
    for suite, cases in CASES.items():
        name = f"day41-{suite}.xml"
        bundle = root / "faults" / f"day41-{suite}-{run_id.replace(':', '-')}"
        if {path.name for path in bundle.iterdir()} != {name}:
            raise ValueError("Unexpected Day41 fault evidence inventory")
        report = (bundle / name).read_bytes()
        xml_cases(report, cases, {}, exact=True)
        proofs[name] = sha256(report).hexdigest()
    receipt = {
        "provenance": facts,
        "enterprise_ci_decision": "VERIFIED",
        "runtime_decision": decision["local_decision"],
        "aws_staging_decision": "BLOCKED",
        "production_authorized": False,
        "proofs_sha256": proofs,
    }
    Path("day41-enterprise.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(
            f"**Enterprise CI:** VERIFIED\n\n**Candidate:** `{facts['day31_commit']}`\n\n"
            f"**Run/attempt:** `{run_id}`\n\n**AWS Staging:** BLOCKED\n"
        )


if __name__ == "__main__":
    main()
