from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import day40_runtime_evidence as day40
from scripts.day39_ci_evidence import write
from scripts.iac.pipeline_evidence import publish


def test_local_evidence_cannot_authorize_aws(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    bundle = tmp_path / "bundle"
    write(
        source / "aggregate.json",
        {"provenance": day40.identity(), "reports": dict.fromkeys(day40.REPORTS, "a" * 64)},
    )
    publish(source, bundle, "aggregate")
    needs = {name: {"result": "success"} for name in day40.REQUIRED}
    monkeypatch.setenv("PIPELINE_NEEDS", json.dumps(needs))
    result = tmp_path / "decision.json"
    assert day40.finalize(bundle, result) == 0
    data = json.loads(result.read_bytes())
    assert data["local_decision"] == "ROTATION_TESTED_LOCAL"
    assert data["aws_staging_decision"] == "BLOCKED"
    assert data["release_authorized"] is False
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "99")
    assert day40.finalize(bundle, result) == 1
    assert json.loads(result.read_bytes())["local_decision"] == "BLOCKED"


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped"])
def test_failed_producer_blocks_day40_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    needs = {name: {"result": "success"} for name in day40.REQUIRED}
    needs["redis"] = {"result": outcome}
    monkeypatch.setenv("PIPELINE_NEEDS", json.dumps(needs))
    result = tmp_path / "decision.json"
    assert day40.finalize(tmp_path / "missing", result) == 1
    assert json.loads(result.read_bytes())["local_decision"] == "BLOCKED"
