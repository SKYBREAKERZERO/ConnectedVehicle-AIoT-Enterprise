"""The visible DAG is the enforced security/test graph, not decorative jobs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> dict[str, Any]:
    return cast(
        dict[str, Any], yaml.load((ROOT / path).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    )


def assert_pinned_steps(workflow: dict[str, Any]) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    text = str(workflow)
    assert "continue-on-error" not in text and "secrets." not in text and "id-token" not in text
    for j in workflow["jobs"].values():
        assert "secrets" not in j and "environment" not in j
        assert j.get("permissions", {"contents": "read"}) == {"contents": "read"}
        if "uses" in j:
            assert j["uses"] in {
                "./.github/workflows/runtime-core.yml",
                "./.github/workflows/runtime-postgres.yml",
                "./.github/workflows/iac-phase.yml",
            }
            continue
        for step in j["steps"]:
            if "uses" in step:
                if step["uses"].startswith("./"):
                    assert step["uses"] in {
                        "./.github/actions/setup-ci-runtime",
                        "./.github/actions/setup-ci-iac",
                    }
                else:
                    assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])


def graph(path: str, final: str, name: str, expected: set[str]) -> dict[str, Any]:
    w = read(path)
    assert_pinned_steps(w)
    assert {"pull_request", "push", "merge_group"} <= w["on"].keys()
    assert "pull_request_target" not in w["on"]
    for event in ("pull_request", "push"):
        assert w["on"][event] == {"branches": ["main"]}
    jobs = w["jobs"]
    assert set(jobs) == expected | {"evidence", final}
    assert jobs[final]["name"] == name and jobs[final]["needs"] == ["evidence"]
    assert jobs[final]["if"] == "${{ always() }}" and jobs["evidence"]["if"] == "${{ always() }}"
    assert set(jobs["evidence"]["needs"]) == expected
    for j, ids in [(jobs[final], {"evidence"}), (jobs["evidence"], expected)]:
        step = next(s for s in j["steps"] if s.get("name") == "Fail closed on all upstream results")
        assert step["env"]["PIPELINE_NEEDS"] == "${{ toJSON(needs) }}"
        assert set(step["run"].split("--expected ", 1)[1].split(",")) == ids
    visited = set()

    def visit(node: str, stack: set[str]) -> None:
        assert node in jobs and node not in stack
        for dep in jobs[node].get("needs", []):
            visit(dep, stack | {node})
        visited.add(node)

    visit(final, set())
    assert visited == set(jobs)
    return w


def commands(*files: str) -> str:
    return "\n".join(
        s.get("run", "")
        for f in files
        for j in read(f)["jobs"].values()
        for s in j.get("steps", [])
    )


def test_day24_runtime_evidence_cannot_be_skipped_or_detached_from_run() -> None:
    w = read(".github/workflows/runtime.yml")
    pg = read(".github/workflows/runtime-postgres.yml")["jobs"]["run"]
    assert w["jobs"]["postgres"]["with"] == {"suite": "postgres"}
    assert w["jobs"]["observability"]["with"] == {"suite": "observability"}
    assert pg["env"]["DAY24_EVIDENCE_RUN_ID"] == "${{ github.run_id }}:${{ github.run_attempt }}"
    step = next(s for s in pg["steps"] if "tests/integration/day24" in s.get("run", ""))
    assert (
        step["if"] == "inputs.suite == 'observability'"
        and "--junitxml=.runtime-reports/day24-postgres-alerts.xml" in step["run"]
    )
    assert "scripts.day24_evidence --check-existing" in step["run"]
    assert pg["env"]["CI_SUITE"] == "${{ inputs.suite }}"
    assert not any("${{ inputs.suite }}" in s.get("run", "") for s in pg["steps"])
    artifact = next(
        s for s in pg["steps"] if s.get("with", {}).get("name") == "day24-campaign-observability"
    )
    assert (
        artifact["with"]["if-no-files-found"] == "error"
        and ".runtime-reports/day24-acceptance.json" in artifact["with"]["path"]
    )


def test_ci_cannot_skip_merge_checks_or_receive_production_secrets() -> None:
    w = graph(
        ".github/workflows/ci.yml",
        "quality",
        "IaC quality gate",
        {"baseline", "lint", "types", "policy", "contracts", "security", "native"},
    )
    for phase in ("contracts", "security", "native"):
        assert w["jobs"][phase]["uses"] == "./.github/workflows/iac-phase.yml"
        expected = {"phase": phase}
        if phase == "contracts":
            expected["contract_group"] = "${{ matrix.contract_group }}"
        assert w["jobs"][phase]["with"] == expected
    from scripts.iac.module_contracts import GROUPS

    assert w["jobs"]["contracts"]["strategy"] == {
        "fail-fast": "false",
        "max-parallel": "4",
        "matrix": {"contract_group": list(GROUPS)},
    }
    phase_workflow = read(".github/workflows/iac-phase.yml")
    assert_pinned_steps(phase_workflow)
    assert phase_workflow["jobs"]["run"]["env"]["CI_PHASE"] == "${{ inputs.phase }}"
    run = next(
        s
        for s in phase_workflow["jobs"]["run"]["steps"]
        if s.get("name") == "Run actual Terraform phase"
    )
    assert '--baseline baseline --phase "$CI_PHASE"' in run["run"]
    assert not any(
        "${{ inputs.phase }}" in s.get("run", "") for s in phase_workflow["jobs"]["run"]["steps"]
    )
    cmd = commands(".github/workflows/ci.yml", ".github/workflows/iac-phase.yml")
    assert "tests/unit/iac" in cmd and "pipeline_evidence assemble-iac" in cmd
    for day in range(27, 32):
        assert f"scripts.iac.day{day}_evidence" in cmd
    final = w["jobs"]["quality"]
    artifact = next(
        s for s in final["steps"] if s.get("with", {}).get("name") == "iac-gate-summary"
    )
    assert artifact["with"]["path"] == ".iac-reports/summary.json"


def test_runtime_gate_cannot_skip_contracts_or_quality_checks() -> None:
    graph(
        ".github/workflows/runtime.yml",
        "runtime",
        "Runtime quality gate",
        {"baseline", "lint", "types", "contracts", "integration", "postgres", "observability"},
    )
    for f in ("runtime-core.yml", "runtime-postgres.yml"):
        assert_pinned_steps(read(".github/workflows/" + f))
    cmd = commands(
        ".github/workflows/runtime.yml",
        ".github/workflows/runtime-core.yml",
        ".github/workflows/runtime-postgres.yml",
    )
    for required in (
        "ruff check .",
        "ruff format --check .",
        "mypy .",
        "scripts.contracts --baseline",
        "scripts.day17_rules",
        "tests/unit tests/contract",
        "tests/e2e/test_independent_runtimes.py",
        "tests/e2e/test_device_full_chain.py",
        "alembic upgrade head",
        "tests/integration/day21",
        "tests/integration/day24",
    ):
        assert required in cmd
    for day in (16, 17, 18, 19):
        assert f"tests/integration/day{day}" in cmd
    for script in (
        "day16_evidence",
        "day17_release",
        "day18_evidence",
        "day19_evidence",
        "day24_evidence",
    ):
        assert f"scripts.{script} --check-existing" in cmd
    for action in ("setup-ci-runtime", "setup-ci-iac"):
        for step in read(f".github/actions/{action}/action.yml")["runs"]["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
