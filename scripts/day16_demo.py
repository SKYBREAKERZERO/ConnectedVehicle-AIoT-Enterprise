"""Run the isolated, free local recovery demonstration and preserve its evidence."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def cleanup_owned(run_id: str) -> None:
    if re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise ValueError("Invalid demo owner")
    result = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "label=cv.day16.run=" + run_id],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    identifiers = result.stdout.split()
    if any(re.fullmatch(r"[0-9a-f]{12,64}", value) is None for value in identifiers):
        raise ValueError("Unexpected container identity")
    if identifiers:
        subprocess.run(
            ["docker", "rm", "-f", *identifiers], capture_output=True, check=True, timeout=20
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["all", "lock", "worker"], default="all")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = (args.output or ROOT / ".runtime-reports" / ("day16-demo-" + uuid4().hex)).resolve()
    # Never reuse a run directory or overwrite an input, prior report or database.
    directory.mkdir(parents=True, exist_ok=False)
    owner = uuid4().hex
    environment = dict(
        os.environ,
        DAY16_EVIDENCE_RUN_ID="demo-" + uuid4().hex,
        RUNTIME_EVIDENCE_DIR=str(directory),
        DAY16_DEMO_CASE=args.scenario,
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
        DAY16_DEMO_OWNER=owner,
    )
    print("Evidence: " + str(directory), flush=True)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/integration/day16/test_demo.py",
                "-q",
                "-s",
                "--tb=short",
            ],
            cwd=ROOT,
            env=environment,
            timeout=240,
        )
        return result.returncode
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        print(
            "Demonstration interrupted or exceeded 240s; cleaning only this run's containers.",
            file=sys.stderr,
        )
        cleanup_owned(owner)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
