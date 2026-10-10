from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml


def test_ci_cannot_skip_merge_checks_or_receive_production_secrets() -> None:
    text = Path(".github/workflows/ci.yml").read_text()
    workflow = cast(dict[str, Any], yaml.load(text, Loader=yaml.BaseLoader))
    events = workflow["on"]
    assert {"pull_request", "push", "merge_group"} <= events.keys()
    assert "pull_request_target" not in events
    assert "paths" not in events["pull_request"]
    assert "paths-ignore" not in events["pull_request"]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["quality"]
    assert job["name"] == "IaC quality gate"
    assert "if" not in job
    assert "secrets." not in text
    assert "continue-on-error" not in text
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
    run = next(s for s in job["steps"] if "scripts.iac.gate" in s.get("run", ""))
    assert "--baseline ../baseline" in run["run"]
    artifact = next(
        s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert artifact["with"]["path"] == "candidate/.iac-reports/summary.json"


def test_runtime_gate_cannot_skip_contracts_or_quality_checks() -> None:
    text = Path(".github/workflows/runtime.yml").read_text()
    workflow = cast(dict[str, Any], yaml.load(text, Loader=yaml.BaseLoader))
    assert {"pull_request", "push", "merge_group"} <= workflow["on"].keys()
    assert "pull_request_target" not in workflow["on"]
    for event in ("pull_request", "push"):
        assert workflow["on"][event]["branches"] == ["main"]
        assert "paths" not in workflow["on"][event]
        assert "paths-ignore" not in workflow["on"][event]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["runtime"]
    assert job["name"] == "Runtime quality gate" and "if" not in job
    assert "continue-on-error" not in text and "secrets." not in text
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    for command in (
        "ruff check .",
        "ruff format --check .",
        "mypy .",
        "scripts.contracts --baseline",
        "tests/e2e/test_independent_runtimes.py",
        "tests/integration/security/test_database_runtime_permissions.py",
    ):
        assert command in commands
    assert not any("if" in step for step in job["steps"])
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
