"""Cross-job replay, corruption and partial-success rejection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.pipeline_evidence import assemble_iac, consume, publish, require_needs, verify


@pytest.fixture(autouse=True)
def isolated_job_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative fixtures must not append fake failure rows to a real job summary.
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", None])
def test_partial_or_skipped_graph_cannot_pass_final_gate(result: str | None) -> None:
    with pytest.raises(ValueError):
        require_needs({"a", "b"}, {"a": {"result": "success"}, "b": {"result": result}})
    with pytest.raises(ValueError):
        require_needs({"a", "b"}, {"a": {"result": "success"}})


@pytest.mark.parametrize(
    "attack", ["tamper", "old-attempt", "extra-file", "wrong-stage", "missing-file"]
)
def test_bundle_rejects_replay_and_unreviewed_data(tmp_path: Path, attack: str) -> None:
    folder = tmp_path / "reports"
    folder.mkdir()
    (folder / "proof.json").write_text("{}")
    output = tmp_path / "bundle"
    publish(folder, output, "iac-policy")
    assert verify(output, "iac-policy")
    if attack == "tamper":
        (output / "proof.json").write_text('{"changed":true}')
    if attack == "old-attempt":
        m = json.loads((output / "manifest.json").read_text())
        m["provenance"]["day31_run_id"] = "1:999"
        (output / "manifest.json").write_text(json.dumps(m))
    if attack == "extra-file":
        (output / "code.py").write_text("raise RuntimeError")
    if attack == "wrong-stage":
        with pytest.raises(ValueError):
            verify(output, "iac-native")
        return
    if attack == "missing-file":
        (output / "proof.json").unlink()
    with pytest.raises(ValueError):
        consume(output, "iac-policy", tmp_path / "accepted")


def test_two_producers_cannot_silently_overwrite_conflicting_evidence(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "proof.json").write_text('{"source":1}')
    (b / "proof.json").write_text('{"source":2}')
    publish(a, tmp_path / "one", "iac-policy")
    publish(b, tmp_path / "two", "iac-native")
    consume(tmp_path / "one", "iac-policy", tmp_path / "accepted")
    with pytest.raises(ValueError):
        consume(tmp_path / "two", "iac-native", tmp_path / "accepted")


def test_native_phase_cannot_manufacture_contract_or_scan_success(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    data: dict[str, dict[str, Any]] = {
        "iac-policy": {"unit.json": {}},
        "iac-contracts": {
            "contracts.json": {
                "status": "passed",
                "phase": "contracts",
                "contract_files": 1,
                "contract_runs": 0,
            }
        },
        "iac-security": {
            "security.json": {
                "status": "passed",
                "phase": "security",
                "security_scan": "passed",
                "scanned_sources": 2,
            }
        },
        "iac-native": {
            "summary.json": {
                "status": "passed",
                "phase": "native",
                "security_scan": "separate-job-required",
            }
        },
    }
    for stage, files in data.items():
        source = tmp_path / stage
        source.mkdir()
        for name, value in files.items():
            (source / name).write_text(json.dumps(value))
        publish(source, inputs / stage, stage)
    with pytest.raises(ValueError, match="contract evidence"):
        assemble_iac(inputs, tmp_path / "out")
