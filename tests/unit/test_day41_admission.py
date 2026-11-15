from typing import Any

import pytest

from scripts import day41_admission as gate
from scripts.day38_readiness import REPO

SHA = "a" * 40


def run(**changes: Any) -> dict[str, Any]:
    return {
        "path": gate.DAY40,
        "head_sha": SHA,
        "event": "push",
        "head_branch": "main",
        "name": "Day40 Runtime Security Closed Loop",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "id": 42,
        "run_attempt": 1,
        "created_at": "2026-11-10T00:00:00Z",
        "status": "completed",
        "conclusion": "success",
        **changes,
    }


def test_pr_or_other_sha_cannot_replace_main_proof() -> None:
    with pytest.raises(ValueError, match="MISSING_MAIN_DAY40"):
        gate.latest_day40([run(event="pull_request"), run(head_sha="b" * 40)], SHA)


@pytest.mark.parametrize("result", ["failure", "cancelled", None])
def test_latest_attempt_cannot_fall_back(result: str | None) -> None:
    with pytest.raises(ValueError, match="LATEST_DAY40_FAILED"):
        gate.latest_day40([run(), run(run_attempt=2, conclusion=result)], SHA)


def test_missing_skipped_or_foreign_job_blocks() -> None:
    jobs = [
        {"name": name, "head_sha": SHA, "status": "completed", "conclusion": "success"}
        for name in sorted(gate.JOBS)
    ]
    gate.require_day40_jobs(jobs, SHA)
    with pytest.raises(ValueError, match="JOB_INVENTORY"):
        gate.require_day40_jobs(jobs[1:], SHA)
    for change in ({"conclusion": "skipped"}, {"head_sha": "b" * 40}):
        with pytest.raises(ValueError, match="JOB_INVENTORY"):
            gate.require_day40_jobs([{**jobs[0], **change}, *jobs[1:]], SHA)


def test_pr_cannot_execute_trusted_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    with pytest.raises(ValueError, match="UNTRUSTED_SOURCE"):
        gate.require_source(SHA)
