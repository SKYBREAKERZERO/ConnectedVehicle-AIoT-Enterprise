"""The fault oracle cannot bless an unexecuted or accidentally successful fault."""

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.iac.pipeline_fault_probe import SCENARIOS, verify_outcomes


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_oracle_requires_failure_at_the_correct_boundary(scenario: str) -> None:
    producer = "skipped" if scenario == "skipped" else "success"
    step = (
        "guard"
        if scenario in {"failure", "skipped"}
        else "download"
        if scenario == "missing-artifact"
        else "verify"
    )
    needs: dict[str, Any] = {
        "producer": {
            "result": producer,
            "outputs": {"operation": "failure" if scenario == "failure" else "success"},
        },
        "consumer": {
            "result": "success",
            "outputs": {"guard": "success", "download": "success", step: "failure"},
        },
    }
    verify_outcomes(scenario, needs)
    for attack in ("unblocked", "missing-output", "wrong-producer"):
        bad = deepcopy(needs)
        if attack == "unblocked":
            bad["consumer"]["outputs"][step] = "success"
        elif attack == "missing-output":
            bad["consumer"]["outputs"] = {}
        else:
            bad["producer"]["result"] = "cancelled"
        with pytest.raises(ValueError):
            verify_outcomes(scenario, bad)


def test_fault_allowances_cannot_replace_production_gates() -> None:
    root = Path(__file__).resolve().parents[3]
    case = yaml.safe_load((root / ".github/workflows/ci-fault-case.yml").read_text())
    assert case["permissions"] == {"contents": "read"}
    assert case["jobs"]["producer"]["continue-on-error"] is True
    assert case["jobs"]["consumer"]["continue-on-error"] is True
    assert not case["jobs"]["oracle"].get("continue-on-error", False)
    assert case["jobs"]["oracle"]["needs"] == ["producer", "consumer"]
    assert case["jobs"]["oracle"]["if"] == "${{ always() }}"
    matrix = yaml.safe_load((root / ".github/workflows/ci-fault-matrix.yml").read_text())
    assert set(matrix["jobs"]["fault"]["strategy"]["matrix"]["scenario"]) == set(SCENARIOS)
    assert matrix["jobs"]["fault"]["strategy"]["matrix"]["graph"] == ["runtime", "iac"]
    for name in (
        "ci.yml",
        "runtime.yml",
        "runtime-core.yml",
        "runtime-postgres.yml",
        "iac-phase.yml",
    ):
        assert "continue-on-error" not in (root / ".github/workflows" / name).read_text()
