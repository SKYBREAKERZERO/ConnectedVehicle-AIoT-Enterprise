"""Opt-in emulator integration. Missing fixture is a failure, never a skip/pass."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from scripts.iac.day27_evidence import source_digest
from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.gate import sandbox_environment
from scripts.iac.state_failure_probe import probe


def test_native_lock_survives_holder_process_termination(
    tmp_path: Path, record_testsuite_property: Callable[[str, object], None]
) -> None:
    provenance = {
        "day27_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day27_run_id": run_identity(),
        "day27_source_sha256": source_digest(),
    }
    for key, value in provenance.items():
        record_testsuite_property(key, value)
    endpoint = os.environ["DAY27_LOCK_ENDPOINT"]
    result = probe(tmp_path / "native-plan", endpoint, sandbox_environment(tmp_path))
    result["provenance"] = provenance
    assert result["holder_process_killed"] and result["orphan_lock_retained"]
    assert result["state_unchanged"] and not result["automatic_force_unlock"]
    assert result["localstack_only"] and not result["aws_verified"]
    path = Path(os.environ["DAY27_LOCK_REPORT"])
    path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
