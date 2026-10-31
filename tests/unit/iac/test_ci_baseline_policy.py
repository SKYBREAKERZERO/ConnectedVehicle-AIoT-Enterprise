"""F01-F04: event-bound baseline refusals and positive event contracts."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.iac.ci_baseline_policy import REPOSITORY, select_baseline

A = "a" * 40
B = "b" * 40
C = "c" * 40


def request() -> dict[str, Any]:
    return {
        "event_name": "pull_request",
        "event": {
            "repository": {"full_name": REPOSITORY, "default_branch": "main"},
            "number": 15,
            "pull_request": {
                "base": {"sha": A, "ref": "main", "repo": {"full_name": REPOSITORY}},
                "head": {"sha": B},
                "merge_commit_sha": C,
                "state": "open",
            },
        },
        "candidate": C,
        "ref": "refs/pull/15/merge",
        "parents": [A, B],
        "ancestor": lambda a, b: True,
        "default_tip": A,
    }


@pytest.mark.parametrize("flow", ["F01", "F02", "F03", "F04"])
def test_baseline_attack_flows_fail_closed(flow: str) -> None:
    args = request()
    if flow == "F01":
        args["event"]["pull_request"]["base"]["sha"] = "0" * 40
    if flow == "F02":
        args["event"]["pull_request"]["base"]["sha"] = C
        args["parents"] = [C, B]
    if flow == "F03":
        args.update(event_name="workflow_dispatch", ref="refs/heads/main", default_tip=C)
        args["event"]["inputs"] = {"baseline": A}
    if flow == "F04":
        args["candidate"] = B
        args["parents"] = [A]
    with pytest.raises(ValueError):
        select_baseline(**args)


@pytest.mark.parametrize("event", ["pull_request", "push", "merge_group", "workflow_dispatch"])
def test_reviewed_event_sources_select_distinct_ancestor(event: str) -> None:
    args = request()
    args["event_name"] = event
    if event == "push":
        args["ref"] = "refs/heads/main"
        args["event"].update(
            before=A, after=C, ref=args["ref"], forced=False, created=False, deleted=False
        )
    if event == "merge_group":
        args["ref"] = "refs/heads/gh-readonly-queue/main/pr-15"
        args["event"]["merge_group"] = {
            "base_sha": A,
            "head_sha": C,
            "base_ref": "refs/heads/main",
            "head_ref": args["ref"],
        }
    if event == "workflow_dispatch":
        args["ref"] = "refs/heads/main"
        args["default_tip"] = C
    assert select_baseline(**args)["baseline_sha"] == A


@pytest.mark.parametrize(
    "mutation", ["nonancestor", "wrong-repo", "wrong-ref", "wrong-parents", "unsupported"]
)
def test_baseline_rejects_untrusted_event_and_history(mutation: str) -> None:
    args = deepcopy(request())
    if mutation == "nonancestor":
        args["ancestor"] = lambda a, b: False
    if mutation == "wrong-repo":
        args["event"]["repository"]["full_name"] = "other/repo"
    if mutation == "wrong-ref":
        args["ref"] = "refs/heads/main"
    if mutation == "wrong-parents":
        args["parents"] = [B, A]
    if mutation == "unsupported":
        args["event_name"] = "pull_request_target"
    with pytest.raises(ValueError):
        select_baseline(**args)


def test_gate_rejects_candidate_workspace_before_external_tools(tmp_path: Any) -> None:
    from scripts.iac.gate import gate

    with pytest.raises(ValueError, match="candidate workspace"):
        gate(
            tmp_path,
            tmp_path,
            work=tmp_path / "work",
            report=tmp_path / "report.json",
            scanner_python="unused",
        )


def test_cached_pr_merge_field_cannot_override_event_git_candidate() -> None:
    args = request()
    args["event"]["pull_request"]["merge_commit_sha"] = A
    assert select_baseline(**args)["candidate_sha"] == C
