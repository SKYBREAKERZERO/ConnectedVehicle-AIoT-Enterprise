"""Require complete runtime and recovery evidence from the current attempt."""

from __future__ import annotations

import json
import os
from pathlib import Path

from scripts.day40_runtime_evidence import identity
from scripts.day41_enterprise_evidence import CASES as DAY41_CASES
from scripts.day41_enterprise_evidence import verify_runtime
from scripts.day42_evidence import CASES as ROLLOUT_CASES
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.pipeline_evidence import verify


def main() -> None:
    root = Path(".day42")
    facts = identity()
    run_id = facts["day31_run_id"]
    suffix = run_id.replace(":", "-")
    bundles = {
        key: root / f"{prefix}-{suffix}"
        for key, prefix in {
            "runtime": "day40-decision",
            "aggregate": "day40-proof-aggregate",
            "recovery": "day42-recovery",
        }.items()
    }
    if set(root.iterdir()) != set(bundles.values()):
        raise ValueError("Missing or unexpected Day42 evidence bundle")
    runtime = verify_runtime(bundles["runtime"], bundles["aggregate"], facts)
    recovery = verify(bundles["recovery"], "day42-recovery")
    cases = {**DAY41_CASES, "rollout": ROLLOUT_CASES}
    if set(recovery) != {f"{suite}.xml" for suite in cases}:
        raise ValueError("Missing or unexpected recovery report")
    for suite, required in cases.items():
        xml_cases((bundles["recovery"] / f"{suite}.xml").read_bytes(), required, {}, exact=True)
    receipt = {
        "provenance": facts,
        "enterprise_ci_decision": "VERIFIED",
        "aws_staging_decision": "BLOCKED",
        "production_authorized": False,
        "proofs_sha256": {**runtime, **recovery},
    }
    Path("day42-enterprise.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(
            f"**Enterprise CI:** VERIFIED\n\n**Candidate:** `{facts['day31_commit']}`\n\n"
            f"**Run/attempt:** `{run_id}`\n\n**AWS Staging:** BLOCKED\n"
        )


if __name__ == "__main__":
    main()
