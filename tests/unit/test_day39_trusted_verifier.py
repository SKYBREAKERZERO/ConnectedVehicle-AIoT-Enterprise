from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import day37_gate as release
from scripts import day38_readiness as offline
from scripts import day39_trusted_verifier as gate

COMMIT = "a" * 40
START = "2026-11-08T10:00:00Z"


def run(**changes: Any) -> dict[str, Any]:
    return {
        "id": 42,
        "run_attempt": 2,
        "head_sha": COMMIT,
        "workflow_id": 99,
        "name": offline.DAY38_NAME,
        "path": offline.DAY38_PATH,
        "event": "push",
        "head_branch": "main",
        "repository": {"full_name": offline.REPO},
        "head_repository": {"full_name": offline.REPO},
        "created_at": "2026-11-08T09:00:00Z",
        "run_started_at": START,
        "status": "completed",
        "conclusion": "success",
        **changes,
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF", "refs/heads/feature/fake-pass"),
        ("GITHUB_WORKFLOW_SHA", "b" * 40),
    ],
)
def test_pr_modified_verifier_cannot_supply_pass(
    monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    for name, expected in {
        "GITHUB_REPOSITORY": offline.REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": COMMIT,
        "GITHUB_WORKFLOW_SHA": COMMIT,
        "GITHUB_WORKFLOW_REF": f"{offline.REPO}/{gate.RELEASE_PATH}@refs/heads/main",
    }.items():
        monkeypatch.setenv(name, expected)
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match="UNTRUSTED_VERIFIER_SOURCE"):
        gate.verify(COMMIT, [run()])


def test_cross_commit_receipt_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    selected = run()
    monkeypatch.setenv("GH_TOKEN", "offline-test")
    monkeypatch.setattr(gate, "require_trusted_source", lambda _: None)
    monkeypatch.setattr(gate.AttemptEvidence, "get", lambda *_: selected)
    monkeypatch.setattr(gate.AttemptEvidence, "artifacts", lambda *_: [])
    monkeypatch.setattr(
        offline,
        "verify_day38_offline",
        lambda *_: {
            "candidate_sha": "b" * 40,
            "run_id": 42,
            "run_attempt": 2,
            "decision": "OFFLINE_AUDIT_PASS",
        },
    )
    with pytest.raises(ValueError, match="COMMIT_MISMATCH"):
        gate.verify(COMMIT, [selected])


def test_older_attempt_jobs_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def response(_: gate.AttemptEvidence, path: str) -> dict[str, Any]:
        assert path == "actions/runs/42/attempts/2/jobs?per_page=100"
        return {"total_count": 1, "jobs": [{"run_id": 42, "run_attempt": 1}]}

    monkeypatch.setattr(gate.AttemptEvidence, "get", response)
    with pytest.raises(ValueError, match="ATTEMPT_REPLAY"):
        gate.AttemptEvidence("offline-test", run()).jobs(42)


def test_renamed_older_attempt_artifact_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        offline.GitHub,
        "artifacts",
        lambda *_: [
            {
                "name": "day38-offline-42-2",
                "created_at": "2026-11-08T09:15:00Z",
                "workflow_run": {"id": 42, "head_sha": COMMIT},
            }
        ],
    )
    with pytest.raises(ValueError, match="ATTEMPT_REPLAY"):
        gate.AttemptEvidence("offline-test", run()).artifacts(42)


def test_tampered_archive_digest_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class Redirect:
        def open(self, *_: Any, **__: Any) -> None:
            headers = Message()
            headers["Location"] = "https://actions.blob.core.windows.net/result.zip"
            raise urllib.error.HTTPError(
                "https://api.github.com",
                302,
                "Found",
                headers,
                None,
            )

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: Redirect())
    monkeypatch.setattr(offline, "fetch_url", lambda *_, **__: b"tampered")
    with pytest.raises(ValueError, match="ZIP digest mismatch"):
        offline.download_artifact(1, "offline-test", hashlib.sha256(b"original").hexdigest())


def test_required_security_job_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = offline.DAY38_REQUIRED_JOB_NAMES[0]
    monkeypatch.setattr(
        gate.AttemptEvidence,
        "get",
        lambda *_: {
            "total_count": len(offline.DAY38_REQUIRED_JOB_NAMES) - 1,
            "jobs": [
                {"name": name, "run_id": 42, "run_attempt": 2, "conclusion": "success"}
                for name in offline.DAY38_REQUIRED_JOB_NAMES
                if name != missing
            ],
        },
    )
    with pytest.raises(ValueError, match="missing"):
        offline.verify_day38_offline(
            gate.AttemptEvidence("offline-test", run()), [run()], COMMIT, "push", "main", COMMIT
        )


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", None])
def test_latest_run_blocks_even_after_older_run_is_rerun(conclusion: str | None) -> None:
    old = run(run_attempt=9, run_started_at="2026-11-08T12:00:00Z")
    latest = run(
        id=43,
        run_attempt=1,
        created_at=START,
        status="in_progress" if conclusion is None else "completed",
        conclusion=conclusion,
    )
    with pytest.raises(ValueError, match="UPSTREAM_FAILED"):
        gate.newest([latest, old], COMMIT)


def test_day37_denies_release_when_security_proof_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": COMMIT,
        "GITHUB_REPOSITORY": release.REPO,
        "GH_TOKEN": "offline-test",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(gate, "require_trusted_source", lambda _: None)
    monkeypatch.setattr(release, "verify_ruleset", lambda _: None)
    monkeypatch.setattr(
        release, "choose_runs", lambda *_: {".github/workflows/day36.yml": {"id": 90}}
    )
    responses = {
        "branches/main": {"commit": {"sha": COMMIT}},
        f"rulesets/{release.RULESET_ID}": {},
        f"actions/runs?head_sha={COMMIT}&per_page=100": {"total_count": 0, "workflow_runs": []},
    }
    monkeypatch.setattr(release, "api", responses.__getitem__)
    with pytest.raises(ValueError, match="MISSING_SECURITY_PROOF"):
        release.admission(COMMIT)

    workflow = Path(__file__).resolve().parents[2] / gate.RELEASE_PATH
    jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]
    assert jobs["admission"]["steps"][0]["with"]["ref"] == "${{ github.workflow_sha }}"
    assert "id-token" not in jobs["admission"].get("permissions", {})
    credentialed_jobs = [
        job for job in jobs.values() if job.get("permissions", {}).get("id-token") == "write"
    ]
    assert credentialed_jobs
    for job in credentialed_jobs:
        assert "admission" in job["needs"]
        assert "needs.admission.result == 'success'" in job["if"]
        assert "github.ref == 'refs/heads/main'" in job["if"]


@pytest.mark.parametrize("allow_bypass", [True, None])
def test_unverifiable_environment_approval_blocks(
    monkeypatch: pytest.MonkeyPatch, allow_bypass: bool | None
) -> None:
    def response(_: offline.GitHub, path: str) -> dict[str, Any]:
        if "deployment-branch-policies" in path:
            return {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        return {
            "can_admins_bypass": allow_bypass,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"id": 1}],
                }
            ],
        }

    monkeypatch.setattr(offline.GitHub, "get", response)
    with pytest.raises(ValueError, match="Unverified protected-main approval environment"):
        gate.require_environment_protection(offline.GitHub("offline-test"))


def test_green_runtime_without_sealed_security_artifact_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = run(
        path=gate.RUNTIME_PATH,
        name=offline.WORKFLOWS[gate.RUNTIME_PATH],
    )
    monkeypatch.setenv("GH_TOKEN", "offline-test")

    def response(_: gate.AttemptEvidence, path: str) -> dict[str, Any]:
        if path == "actions/runs/42/attempts/2":
            return selected
        if path.endswith("/jobs?per_page=100"):
            return {
                "total_count": 1,
                "jobs": [
                    {
                        "name": offline.FINAL_JOBS[gate.RUNTIME_PATH],
                        "run_id": 42,
                        "run_attempt": 2,
                        "conclusion": "success",
                    }
                ],
            }
        assert path == "actions/runs/42/artifacts?per_page=100"
        return {"total_count": 0, "artifacts": []}

    monkeypatch.setattr(gate.AttemptEvidence, "get", response)
    with pytest.raises(ValueError, match="missing/duplicate required artifact"):
        gate.verify_runtime(COMMIT, selected)
