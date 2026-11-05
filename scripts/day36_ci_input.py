"""Read-only branch-local CI audit. This is NOT trusted-main release promotion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.iac.workflow_evidence_binding import GitHub, live


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = live(GitHub(), args.pr)
    result["verification_mode"] = "branch-local-staging-precheck"
    result["production_authorized"] = False
    if args.compare and json.loads(args.compare.read_text()) != result:
        raise ValueError("CI evidence, candidate or governance changed during staging")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
