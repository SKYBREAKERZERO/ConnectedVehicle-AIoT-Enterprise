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
