"""Exercise the actual standalone workflow's final authorization guard."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.unit.iac.test_workflow import assert_pinned_steps, read


def test_day34_calls_the_complete_chain_without_shared_cancellation_or_secrets() -> None:
    workflow = read(".github/workflows/day34.yml")
    runtime = read(".github/workflows/runtime.yml")
    assert_pinned_steps(workflow)
    assert "workflow_call" in runtime["on"]
    assert set(workflow["on"]) == {"pull_request", "push", "merge_group", "workflow_dispatch"}
    assert workflow["jobs"]["acceptance"]["uses"] == "./.github/workflows/runtime.yml"
    final = workflow["jobs"]["day34"]
    assert final["needs"] == ["acceptance"] and final["if"] == "${{ always() }}"
    assert "--expected acceptance" in final["steps"][1]["run"]
    assert "${{ github.workflow }}" in runtime["concurrency"]["group"]
    assert runtime["concurrency"]["group"].startswith("runtime-")
    assert workflow["concurrency"]["group"].startswith("day34-entry-")
    assert any("--stage runtime-evidence" in s.get("run", "") for s in final["steps"])


@pytest.mark.parametrize("fault", ["none", "release", "ci", "commit", "run", "decision", "missing"])
def test_day34_final_workflow_guard_refuses_invalid_acceptance(tmp_path: Path, fault: str) -> None:
    workflow = read(".github/workflows/day34.yml")
    script = next(
        s["run"]
        for s in workflow["jobs"]["day34"]["steps"]
        if s.get("name") == "Confirm Day34 acceptance and closed release authorization"
    )
    code = "\n".join(script.strip().splitlines()[1:-1])
    commit = "a" * 40
    proof = dict(
        decision="READY_FOR_LOCAL_REVIEW",
        ci_verified=True,
        release_authorized=False,
        real_aws_verified=False,
        physical_boot_verified=False,
        simulated_installation=True,
        provenance=dict(commit=commit, run_id="123:1"),
        proofs={},
    )
    if fault in {"release", "ci"}:
        proof["release_authorized" if fault == "release" else "ci_verified"] = fault == "release"
    elif fault in {"commit", "run"}:
        proof["provenance"]["commit" if fault == "commit" else "run_id"] = "other"  # type: ignore[index]
    elif fault == "decision":
        proof["decision"] = "BLOCKED"
    root = tmp_path / ".day34-input"
    root.mkdir()
    if fault != "missing":
        (root / "day34-acceptance.json").write_text(json.dumps(proof))
    (root / "day31-runtime-baseline.json").write_text(
        json.dumps(
            dict(
                candidate_sha=commit,
                pr_head_sha="b" * 40,
            )
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
        env=dict(
            os.environ,
            GITHUB_SHA=commit,
            DAY16_EVIDENCE_RUN_ID="123:1",
            GITHUB_STEP_SUMMARY=str(tmp_path / "summary.md"),
        ),
    )
    assert (result.returncode == 0) is (fault == "none"), result.stderr.decode()
    output = tmp_path / "day34-workflow-result.json"
    if fault == "none":
        assert json.loads(output.read_text())["release_authorized"] is False
    else:
        assert not output.exists()
