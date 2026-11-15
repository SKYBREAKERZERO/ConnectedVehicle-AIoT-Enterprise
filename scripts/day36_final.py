"""Durable final decision: all five DAG nodes and independent proof must qualify."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from scripts.day35_workflow_gate import load
from scripts.day36_supply import context
from scripts.iac.pipeline_evidence import require_needs, verify


def evaluate(folder: Path, needs: dict[str, Any]) -> dict[str, Any]:
    require_needs({"intake", "image", "staging", "evidence"}, needs)
    files = verify(folder, "day36-final")
    if set(files) != {"decision.json"}:
        raise ValueError("Exact independent decision artifact required")
    result = load(folder / "decision.json")
    if (
        result["decision"] != "READY_FOR_STAGING_REVIEW"
        or any(result[k] != v for k, v in context().items())
        or result["supply_chain"]["decision"] != "SUPPLY_CHAIN_VERIFIED"
        or any(
            result[k] is not False
            for k in (
                "production_authorized",
                "release_authorized",
                "trusted_main_release_verified",
                "formal_image_publication_verified",
                "cloud_rollout_verified",
            )
        )
    ):
        raise ValueError("Final source/attempt/supply-chain/authority mismatch")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(args.folder, json.loads(os.environ.get("PIPELINE_NEEDS", "{}")))
    except (ValueError, OSError, KeyError, TypeError) as error:
        result = {
            "decision": "BLOCKED",
            "production_authorized": False,
            "release_authorized": False,
            "reason": str(error),
            **context(),
        }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(
                "## Day36\n\n" + result["decision"] + ". Production authorized: **false**.\n"
            )
    if result["decision"] == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
