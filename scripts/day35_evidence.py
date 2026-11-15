"""Day35 exact-source runtime fault admission; review readiness never grants Apply."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

from scripts import day34_evidence
from scripts.iac.day31_evidence import xml_cases

REQUIRED = {
    "test_wave_job_audit_rollback_then_replay_preserves_single_effect",
    "test_confirmed_boot_audit_failure_reconciles_without_second_install",
}


def evaluate(directory: Path) -> dict[str, Any]:
    expected = day34_evidence.binding()
    if os.environ.get("GITHUB_ACTIONS") == "true" and (
        expected["commit"] != os.environ.get("GITHUB_SHA")
        or expected["run_id"]
        != f"{os.environ.get('GITHUB_RUN_ID')}:{os.environ.get('GITHUB_RUN_ATTEMPT')}"
    ):
        raise ValueError("GitHub commit/run/attempt mismatch")
    prior = day34_evidence.evaluate(directory)
    prior_bytes = (directory / "day34-acceptance.json").read_bytes()
    if json.loads(prior_bytes) != prior:
        raise ValueError("Day34 acceptance changed or replayed")
    raw = (directory / "day35-runtime-faults.xml").read_bytes()
    xml_cases(raw, REQUIRED, expected, exact=True)
    return dict(
        version=1,
        decision="READY_FOR_LOCAL_REVIEW",
        provenance=expected,
        required_cases=sorted(REQUIRED),
        proofs={
            "day35-runtime-faults.xml": hashlib.sha256(raw).hexdigest(),
            "day34-acceptance.json": hashlib.sha256(prior_bytes).hexdigest(),
        },
        release_authorized=False,
        real_aws_verified=False,
        physical_boot_verified=False,
        simulated_installation=True,
        ci_verified=prior["ci_verified"],
    )


def check_existing(directory: Path) -> None:
    result = json.loads((directory / "day35-acceptance.json").read_text(encoding="utf-8"))
    day34_evidence.fresh(result)
    expected = evaluate(directory)
    if {k: v for k, v in result.items() if k != "generated_at_utc"} != expected:
        raise ValueError("Day35 acceptance or report bytes changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(os.getenv("RUNTIME_EVIDENCE_DIR", ".runtime-reports")),
    )
    parser.add_argument("--check-existing", action="store_true")
    args = parser.parse_args()
    try:
        if args.check_existing:
            check_existing(args.directory)
            print("Day35 existing evidence verified; release remains unauthorized")
            return 0
        result = evaluate(args.directory)
    except (OSError, ValueError, KeyError, TypeError, ParseError) as exc:
        result = dict(
            decision="BLOCKED",
            release_authorized=False,
            real_aws_verified=False,
            physical_boot_verified=False,
            reason=str(exc),
        )
    if args.check_existing:
        print(json.dumps(result, indent=2))
        return 1
    result["generated_at_utc"] = datetime.now(UTC).isoformat()
    day34_evidence.write(args.directory / "day35-acceptance.json", result)
    print(json.dumps(result, indent=2))
    return 1 if result["decision"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
