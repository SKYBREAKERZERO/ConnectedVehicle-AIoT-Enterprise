"""Verify both Day42 acceptance chains before issuing a CI receipt."""

from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

from scripts.day38_readiness import HASH, strict_json
from scripts.day40_runtime_evidence import identity
from scripts.day42_evidence import CASES
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.pipeline_evidence import verify


def main() -> None:
    root = Path(".day42")
    facts = identity()
    runtime_raw = (root / "runtime/day41-enterprise.json").read_bytes()
    rollout_raw = (root / "rollout/day42-acceptance.json").read_bytes()
    runtime = strict_json(runtime_raw)
    rollout = strict_json(rollout_raw)
    proofs = verify(root / "proof", "day42-rollout")
    if (
        runtime["provenance"] != facts
        or rollout["provenance"] != facts
        or runtime["enterprise_ci_decision"] != "VERIFIED"
        or runtime["runtime_decision"] != "ROTATION_TESTED_LOCAL"
        or runtime["aws_staging_decision"] != "BLOCKED"
        or rollout["offline_decision"] != "VERIFIED"
        or rollout["staging_decision"] != "BLOCKED"
        or runtime["production_authorized"] is not False
        or rollout["production_authorized"] is not False
        or set(proofs) != {"rollout.xml"}
        or rollout["proofs_sha256"] != proofs
    ):
        raise ValueError("Day42 source, attempt, evidence or authorization mismatch")
    runtime_proofs = runtime["proofs_sha256"]
    if set(runtime_proofs) != {
        "runtime_decision",
        "aggregate.json",
        "day41-rotation.xml",
        "day41-admission.xml",
    } or any(
        not isinstance(value, str) or not HASH.fullmatch(value) for value in runtime_proofs.values()
    ):
        raise ValueError("Incomplete runtime evidence")
    xml_cases((root / "proof/rollout.xml").read_bytes(), CASES, {}, exact=True)
    receipt = {
        "provenance": facts,
        "enterprise_ci_decision": "VERIFIED",
        "aws_staging_decision": "BLOCKED",
        "production_authorized": False,
        "proofs_sha256": {
            "day41-enterprise.json": sha256(runtime_raw).hexdigest(),
            "day42-acceptance.json": sha256(rollout_raw).hexdigest(),
            **proofs,
        },
    }
    Path("day42-enterprise.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(
            f"**Enterprise CI:** VERIFIED\n\n**Candidate:** `{facts['day31_commit']}`\n\n"
            f"**Run/attempt:** `{facts['day31_run_id']}`\n\n**AWS Staging:** BLOCKED\n"
        )


if __name__ == "__main__":
    main()
