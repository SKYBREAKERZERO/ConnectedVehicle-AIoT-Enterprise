"""Repeat the complete local resilience + SLO release-readiness exercise."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from scripts.day16_demo import cleanup_owned
from scripts.day17_release import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    directory = (args.output or ROOT / ".runtime-reports" / ("day17-" + uuid4().hex)).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    owner = uuid4().hex
    environment = dict(
        os.environ,
        DAY16_EVIDENCE_RUN_ID="day17-" + uuid4().hex,
        RUNTIME_EVIDENCE_DIR=str(directory),
        DAY16_DEMO_OWNER=owner,
        DAY16_DEMO_CASE="all",
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
    )
    print("Local-only operational evidence: " + str(directory), flush=True)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/integration/day16",
                "tests/integration/day17",
                "-q",
                "-s",
                "--tb=short",
            ],
            cwd=ROOT,
            env=environment,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
            start_new_session=sys.platform != "win32",
        )
        code = process.wait(timeout=360)
        if code:
            return code
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.day17_release",
                "--directory",
                str(directory),
                "--check-existing",
            ],
            cwd=ROOT,
            env=environment,
            timeout=30,
        ).returncode
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        if process is not None and process.poll() is None:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        cleanup_owned(owner)
        print("Drill deadline/interruption: this run's containers were cleaned", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
