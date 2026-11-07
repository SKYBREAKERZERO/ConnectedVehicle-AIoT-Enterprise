"""Day37 independent finalization with explicit Bootstrap reconciliation job.

The legacy Day37 gate expects exactly ten jobs. This adapter first checks the
complete enterprise DAG, then passes only the original ten to the existing
artifact/evidence verifier; it never upgrades a failed status to success.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from scripts.day37_fence import Blocked, require, write
from scripts.day37_release_guard import ALL_JOBS, JOB_SETS, final_check


def verify_dag(mode: str, statuses: dict[str, Any]) -> None:
    require(mode in JOB_SETS, "unsupported release mode")
    require(set(statuses) == ALL_JOBS, "unexpected/missing enterprise job")
    required = JOB_SETS[mode]
    for name in ALL_JOBS:
        require(isinstance(statuses[name], dict), "malformed needs node")
        expected = "success" if name in required else "skipped"
        require(statuses[name].get("result") == expected, f"{name} must be {expected}")


def evaluate(mode: str, needs: dict[str, Any], folder: Path, commit: str,
             run_id: str, attempt: str) -> dict[str, Any]:
    verify_dag(mode, needs)
    # Imported only after the full needs map was authenticated.
    from scripts.day37_gate import final
    old = {key: value for key, value in needs.items() if key != "bootstrap_close"}
    return final(mode, old, folder, commit, run_id, attempt)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=sorted(JOB_SETS), required=True)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        needs = json.loads(os.environ["PIPELINE_NEEDS"])
        require(isinstance(needs, dict), "PIPELINE_NEEDS not an object")
        result = evaluate(args.mode, needs, args.folder,
                          os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"],
                          os.environ["GITHUB_RUN_ATTEMPT"])
        write(args.output, result)
        # Do not publish a success JSON if the separately authored proof fails.
        final_check(args.mode, str(args.folder), str(args.output))
        if args.mode in ('bootstrap','deploy'):
            from scripts.day37_approval import final_verify, reviews
            from scripts.day37_fence import env, load
            phase=args.mode
            base='plan' if phase=='bootstrap' else 'deploy-plan'
            record=load(args.folder/('bootstrap/approval.json' if phase=='bootstrap' else 'deploy/approval.json'))
            receipt=load(args.folder/base/'receipt.json')
            final_verify(record,phase,receipt,reviews(),actor=env('GITHUB_ACTOR'))
        return 0
    except (ValueError, Blocked, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        write(args.output, {
            "decision": "BLOCKED", "reason": type(exc).__name__, "mode": args.mode,
            "commit": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "production_authorized": False, "release_authorized": False,
        })
        print("BLOCKED: enterprise final gate rejected: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
