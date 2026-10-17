from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from enterprise_platform.reliability.slo import CanaryWindow, MetricsDelta, Probe, evaluate_window
from scripts.day17_release import github_gate, read_json, write_json
from scripts.day17_rules import RULES, generated, policy


def window(
    *, failures: int = 0, count: int = 100, latency: float = 0.1, age: float = 0
) -> CanaryWindow:
    end = datetime.now(UTC) - timedelta(seconds=age)
    return CanaryWindow(
        window_id="a" * 32,
        phase="recovered",
        started_at=end - timedelta(seconds=1),
        ended_at=end,
        route="/health/ready",
        samples=[
            Probe(status=503 if index < failures else 200, elapsed_seconds=latency)
            for index in range(count)
        ],
        metrics_delta=MetricsDelta(requests=count, errors=failures, duration_count=count),
    )


@pytest.mark.parametrize(
    "failures,expected", [(0, "proceed"), (1, "proceed"), (2, "abort"), (5, "abort")]
)
def test_exact_error_budget_boundaries(failures: int, expected: str) -> None:
    result = evaluate_window(window(failures=failures), policy(), now=datetime.now(UTC))
    assert result["decision"] == expected


@pytest.mark.parametrize("change", [{"count": 99}, {"latency": 1.01}, {"age": 901}, {"age": -60}])
def test_slo_rejects_insufficient_slow_stale_and_future_evidence(change: dict[str, Any]) -> None:
    assert evaluate_window(window(**change), policy(), now=datetime.now(UTC))["decision"] == "abort"


def test_metrics_and_samples_must_reconcile() -> None:
    row = window().model_dump()
    row["metrics_delta"] = MetricsDelta(requests=100, errors=1, duration_count=100)
    with pytest.raises(ValidationError):
        CanaryWindow.model_validate(row)
    with pytest.raises(ValidationError):
        Probe(status=200, elapsed_seconds=float("nan"))


def test_policy_cannot_silently_weaken_baseline() -> None:
    row = policy().model_dump()
    row["readiness_availability"] = 0.9
    with pytest.raises(ValidationError):
        type(policy()).model_validate(row)
    assert RULES.read_text() == generated()


def remote_fixture() -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    metadata = {"head": {"sha": "a" * 40}, "merge_commit_sha": "b" * 40}
    protection = {
        "enforce_admins": {"enabled": True},
        "required_status_checks": {
            "strict": True,
            "checks": [
                {"context": "Runtime quality gate", "app_id": 15368},
                {"context": "IaC quality gate", "app_id": 15368},
            ],
        },
    }
    runs = [
        dict(
            id=index,
            run_attempt=1,
            name=name,
            path=path,
            head_sha="a" * 40,
            event="pull_request",
            status="completed",
            conclusion="success",
        )
        for index, (name, path) in enumerate(
            (
                ("Runtime quality gates", ".github/workflows/runtime.yml"),
                ("IaC quality gates", ".github/workflows/ci.yml"),
            ),
            100,
        )
    ]
    return metadata, protection, runs


def test_exact_head_remote_gate() -> None:
    metadata, protection, runs = remote_fixture()
    assert github_gate("a" * 40, "b" * 40, metadata, protection, runs)["trusted_checks_enforced"]


@pytest.mark.parametrize(
    "case",
    [
        "head",
        "merge",
        "pending",
        "failed",
        "rerun",
        "newer_failed",
        "app",
        "strict",
        "admins",
        "path",
    ],
)
def test_remote_release_rejects_unsafe_metadata(case: str) -> None:
    metadata, protection, runs = remote_fixture()
    merge = "b" * 40
    if case == "head":
        metadata["head"]["sha"] = "c" * 40
    elif case == "merge":
        merge = "d" * 40
    elif case == "pending":
        runs[0]["status"] = "in_progress"
    elif case == "failed":
        runs[0]["conclusion"] = "failure"
    elif case == "rerun":
        runs[0].update(run_attempt=2, status="queued")
    elif case == "newer_failed":
        runs.append(dict(runs[0], id=102, conclusion="failure"))
    elif case == "app":
        protection["required_status_checks"]["checks"][0]["app_id"] = 1
    elif case == "strict":
        protection["required_status_checks"]["strict"] = False
    elif case == "admins":
        protection["enforce_admins"]["enabled"] = False
    elif case == "path":
        runs[0]["path"] = ".github/workflows/pretend.yml"
    with pytest.raises(ValueError):
        github_gate("a" * 40, merge, metadata, protection, runs)


def test_operational_reports_never_overwrite(tmp_path: Path) -> None:
    path = write_json(tmp_path / "report.json", {"decision": "abort"})
    with pytest.raises(FileExistsError):
        write_json(path, {"decision": "proceed"})
    assert read_json(path)["decision"] == "abort"
    bad = tmp_path / "duplicate.json"
    bad.write_text('{"decision":"abort","decision":"proceed"}')
    with pytest.raises(ValueError):
        read_json(bad)
