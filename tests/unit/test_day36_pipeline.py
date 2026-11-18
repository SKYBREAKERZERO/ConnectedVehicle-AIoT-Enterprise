"""Real Workflow/CLI contracts: prevent missing nodes, flags and rollback arguments."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.day36_lock import packages, validate
from scripts.day36_staging import ROOT
from scripts.day36_supply import context


@pytest.fixture(scope="module", autouse=True)
def junit_context(record_testsuite_property: Callable[[str, str], None]) -> None:
    for key, value in context().items():
        record_testsuite_property(key, value)


def test_workflow_five_nodes_and_python_interfaces() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/day36.yml").read_text())
    jobs = workflow["jobs"]
    expected = {
        "intake": set(),
        "image": {"intake"},
        "staging": {"intake", "image"},
        "evidence": {"intake", "image", "staging"},
        "gate": {"intake", "image", "staging", "evidence"},
    }
    assert set(jobs) == set(expected)
    for name, deps in expected.items():
        needs = jobs[name].get("needs", [])
        assert set([needs] if isinstance(needs, str) else needs) == deps
    assert all(value == "read" for value in workflow["permissions"].values())
    assert "always()" in jobs["gate"]["if"]
    commands = "\n".join(s.get("run", "") for j in jobs.values() for s in j["steps"])
    assert "scripts.day36_release" not in commands
    assert "--archives .day36-images" in commands
    assert "pytest tests/integration/day36" in commands
    assert "scripts.day36_supply scan" in commands
    assert "scripts.day36_supply load --folder .day36-verify" in commands
    for module, options in {
        "scripts.day36_build": ["--baseline", "--output", "--archives"],
        "scripts.day36_staging": ["--baseline-image", "--candidate-image", "--output"],
        "scripts.day36_supply": ["--folder", "--archives", "--cache"],
        "scripts.day36_evidence": ["--folder", "--ci", "--output"],
        "scripts.day36_final": ["--folder", "--output"],
    }.items():
        help_text = subprocess.check_output(
            [sys.executable, "-m", module, "--help"], cwd=ROOT, text=True
        )
        assert all(option in help_text for option in options)
    integration = (ROOT / "tests/integration/day36/test_staging.py").read_text()
    assert 'images["baseline"]["image_digest"]' in integration
    assert 'images["candidate"]["image_digest"]' in integration
    validate()


@pytest.mark.parametrize(
    "line",
    [
        "requests>=2",
        "requests==2.0",
        "-r other.txt",
        "requests==2.0 --hash=sha256:bad",
        "requests==2.0 --hash=sha256:" + "a" * 64 + "\nrequests==3.0 --hash=sha256:" + "b" * 64,
    ],
)
def test_lock_file_rejects_partial_or_unhashed_requirements(tmp_path: Path, line: str) -> None:
    path = tmp_path / "bad.lock"
    path.write_text(line)
    with pytest.raises(ValueError):
        packages(path)


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
def test_final_gate_persists_blocked_without_upstream_proof(tmp_path: Path, result: str) -> None:
    output = tmp_path / "decision.json"
    import json

    environment = {
        **os.environ,
        "PIPELINE_NEEDS": json.dumps(
            {
                n: {"result": result if n == "image" else "success"}
                for n in ("intake", "image", "staging", "evidence")
            }
        ),
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.day36_final",
            "--folder",
            str(tmp_path),
            "--output",
            str(output),
        ],
        env=environment,
        cwd=ROOT,
        capture_output=True,
    )
    decision: dict[str, Any] = json.loads(output.read_text())
    assert completed.returncode != 0 and decision["decision"] == "BLOCKED"
    assert decision["production_authorized"] is False
