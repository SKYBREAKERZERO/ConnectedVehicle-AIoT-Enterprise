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
    from tests.unit.iac.test_module_contracts import reports

    for group, report in reports().items():
        data[f"iac-contracts-{group}"] = {f"contracts-{group}.json": report}
    data["iac-contracts-foundation"]["contracts-foundation.json"]["contract_runs"] = 0
    for stage, files in data.items():
        source = tmp_path / stage
        source.mkdir()
        for name, value in files.items():
            (source / name).write_text(json.dumps(value))
        publish(source, inputs / stage, stage)
    with pytest.raises(ValueError, match="contract evidence"):
        assemble_iac(inputs, tmp_path / "out")


def test_independent_module_bundles_merge_without_double_counting(tmp_path: Path) -> None:
    from scripts.iac.module_contracts import GROUPS
    from tests.unit.iac.test_module_contracts import reports

    inputs = tmp_path / "inputs"
    payloads: dict[str, dict[str, Any]] = {
        "iac-policy": {"policy.json": {}},
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
                "contract_runs": 0,
            }
        },
    }
    for group, report in reports().items():
        payloads[f"iac-contracts-{group}"] = {f"contracts-{group}.json": report}
    for stage, files in payloads.items():
        source = tmp_path / stage
        source.mkdir()
        for name, value in files.items():
            (source / name).write_text(json.dumps(value))
        publish(source, inputs / stage, stage)
    output = tmp_path / "combined"
    assemble_iac(inputs, output)
    summary = json.loads((output / "summary.json").read_text())
    combined = json.loads((output / "contracts.json").read_text())
    assert summary["contract_runs"] == sum(len(roots) for roots in GROUPS.values()) == 17
    assert combined["contract_runs"] == summary["contract_runs"]
    assert summary["module_contract_groups"] == list(GROUPS)


# Read the actual declared dependency sets; every mandatory node is faulted.
def dag_fault_cases() -> list[tuple[str, str, str | None]]:
    import yaml

    root = Path(__file__).resolve().parents[3]
    return [
        (workflow, node, outcome)
        for workflow in ("ci.yml", "runtime.yml")
        for node in yaml.safe_load((root / ".github/workflows" / workflow).read_text())["jobs"][
            "evidence"
        ]["needs"]
        for outcome in ("failure", "cancelled", "skipped", None)
    ]


@pytest.mark.parametrize("workflow,node,outcome", dag_fault_cases())
def test_every_declared_upstream_fault_blocks_evidence(
    workflow: str, node: str, outcome: str | None
) -> None:
    import yaml

    root = Path(__file__).resolve().parents[3]
    expected = set(
        yaml.safe_load((root / ".github/workflows" / workflow).read_text())["jobs"]["evidence"][
            "needs"
        ]
    )
    actual = {name: {"result": "success"} for name in expected}
    if outcome is None:
        del actual[node]
    else:
        actual[node]["result"] = outcome
    with pytest.raises(ValueError):
        require_needs(expected, actual)


@pytest.mark.parametrize("workflow", ["ci.yml", "runtime.yml"])
@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped", None])
def test_final_gate_rejects_every_non_success_evidence(workflow: str, outcome: str | None) -> None:
    import yaml

    root = Path(__file__).resolve().parents[3]
    document = yaml.safe_load((root / ".github/workflows" / workflow).read_text())
    gate = "quality" if workflow == "ci.yml" else "runtime"
    expected = set(document["jobs"][gate]["needs"])
    assert expected == {"evidence"}
    with pytest.raises(ValueError):
        require_needs(expected, {} if outcome is None else {"evidence": {"result": outcome}})


@pytest.mark.parametrize("workflow", ["ci.yml", "runtime.yml"])
def test_complete_actual_dependency_graph_is_accepted(workflow: str) -> None:
    import yaml

    root = Path(__file__).resolve().parents[3]
    document = yaml.safe_load((root / ".github/workflows" / workflow).read_text())
    expected = set(document["jobs"]["evidence"]["needs"])
    require_needs(expected, {node: {"result": "success"} for node in expected})
