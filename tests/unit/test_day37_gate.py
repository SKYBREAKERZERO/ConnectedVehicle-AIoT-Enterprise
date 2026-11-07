from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import day37_gate as gate

COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


def make_plan(enabled: bool = False, digest: str | None = None) -> dict[str, Any]:
    variables = {"enable_service": {"value": enabled}, "image_digest": {"value": digest}}
    data: dict[str, Any] = {
        "variables": variables,
        "resource_changes": [
            {
                "address": "aws_ecr_repository.api",
                "type": "aws_ecr_repository",
                "change": {"actions": ["no-op"]},
            }
        ],
    }
    if enabled:
        task = {
            "type": "aws_ecs_task_definition",
            "values": {
                "container_definitions": json.dumps(
                    [{"name": "vehicle-api", "image": "repo@" + str(digest)}]
                )
            },
        }
        data["planned_values"] = {"root_module": {"resources": [task]}}
    return data


def test_plan_only_with_no_service_is_valid() -> None:
    p = gate.plan_check(make_plan())
    assert p["decision"] == "NON_DESTRUCTIVE_TERRAFORM_PLAN"
    assert p["release_authorized"] is False


def test_digest_deployment_must_match_exact_task() -> None:
    p = gate.plan_check(make_plan(True, DIGEST), expected_digest=DIGEST)
    assert p["service_enabled"] is True


@pytest.mark.parametrize(
    "actions", [["delete"], ["delete", "create"], ["replace"], ["create", "delete"], []]
)
def test_destructive_or_unknown_actions_blocked(actions: list[str]) -> None:
    p = make_plan()
    p["resource_changes"][0]["change"]["actions"] = actions
    with pytest.raises(ValueError):
        gate.plan_check(p)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-digest",
        "mutable-image",
        "missing-task",
        "service-disabled",
        "plan-mode-service-enabled",
    ],
)
def test_plan_rejects_invalid_registry_identity(mutation: str) -> None:
    p = make_plan(True, DIGEST)
    expected: str | None = DIGEST
    if mutation == "wrong-digest":
        expected = "sha256:" + "c" * 64
    elif mutation == "mutable-image":
        p["planned_values"]["root_module"]["resources"][0]["values"]["container_definitions"] = (
            json.dumps([{"image": "repo:latest"}])
        )
    elif mutation == "missing-task":
        p["planned_values"]["root_module"]["resources"] = []
    elif mutation == "service-disabled":
        p["variables"]["enable_service"]["value"] = False
    elif mutation == "plan-mode-service-enabled":
        expected = None
    with pytest.raises(ValueError):
        gate.plan_check(p, expected_digest=expected)


def test_dag_missing_node_denied() -> None:
    with pytest.raises(ValueError):
        gate.final("audit", {"source": {"result": "success"}}, Path("unused"), COMMIT, "123", "1")


def test_audit_mode_requires_every_other_job_skipped() -> None:
    names = [
        "source",
        "admission",
        "plan",
        "bootstrap",
        "publish",
        "deploy",
        "verify",
        "close",
        "recovery",
        "deploy_plan",
    ]
    needs = {n: {"result": "success" if n == "source" else "skipped"} for n in names}
    out = gate.final("audit", needs, Path("unused"), COMMIT, "123", "1")
    assert out["decision"] == "READY_FOR_CONFIGURATION_REVIEW"
    assert out["real_aws_verified"] is False
    needs["verify"]["result"] = "success"
    with pytest.raises(ValueError):
        gate.final("audit", needs, Path("unused"), COMMIT, "123", "1")


@pytest.mark.parametrize(
    "job",
    [
        "source",
        "admission",
        "plan",
        "bootstrap",
        "publish",
        "deploy",
        "verify",
        "close",
        "recovery",
        "deploy_plan",
    ],
)
def test_failures_never_promote(job: str) -> None:
    required = {"source", "admission", "publish", "deploy", "verify", "deploy_plan", "close"}
    names = {
        "source",
        "admission",
        "plan",
        "bootstrap",
        "publish",
        "deploy",
        "verify",
        "close",
        "recovery",
        "deploy_plan",
    }
    needs = {n: {"result": "success" if n in required else "skipped"} for n in names}
    needs[job]["result"] = "failure"
    with pytest.raises(ValueError):
        gate.final("deploy", needs, Path("unused"), COMMIT, "123", "1")


def test_main_only_and_sha_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/15/merge")
    monkeypatch.setenv("GITHUB_SHA", COMMIT)
    monkeypatch.setenv("GITHUB_REPOSITORY", gate.REPO)
    with pytest.raises(ValueError, match="protected-main"):
        gate.admission(COMMIT)


def test_strict_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "fake.json"
    path.write_text('{"decision":"PASS","decision":"BLOCKED"}')
    with pytest.raises(ValueError, match="Duplicate"):
        gate.strict_load(path)


def test_latest_failed_upstream_blocks_even_if_old_success() -> None:
    rows = []
    for i, path in enumerate(sorted(gate.REQUIRED_WORKFLOWS)):
        rows.append(
            {
                "path": path,
                "head_sha": COMMIT,
                "head_branch": "main",
                "event": "push",
                "run_started_at": "2026-11-06T09:00:00Z",
                "run_attempt": 1,
                "id": i + 1,
                "status": "completed",
                "conclusion": "success",
            }
        )
    rows.append(
        {**rows[0], "id": 99, "run_started_at": "2026-11-06T10:00:00Z", "conclusion": "failure"}
    )
    with pytest.raises(ValueError, match="latest successful"):
        gate.choose_runs(rows, COMMIT)


def test_main_ruleset_bypass_fails_closed() -> None:
    rules = {
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [],
    }
    with pytest.raises(ValueError):
        gate.verify_ruleset(rules)
