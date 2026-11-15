"""Verify Day38 proof using only the protected-main Day37 workflow checkout."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from scripts import day38_readiness as offline

RUNTIME_PATH = ".github/workflows/runtime.yml"
RELEASE_PATH = ".github/workflows/day37-aws-staging.yml"
ENVIRONMENTS = (
    "aws-staging-plan",
    "aws-staging-bootstrap",
    "aws-staging-publish",
    "aws-staging-deploy",
    "aws-staging-verify",
    "aws-staging-recovery",
)


def require_trusted_source(commit: str) -> None:
    expected = {
        "GITHUB_REPOSITORY": offline.REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": commit,
        "GITHUB_WORKFLOW_SHA": commit,
        "GITHUB_WORKFLOW_REF": f"{offline.REPO}/{RELEASE_PATH}@refs/heads/main",
    }
    if not offline.SHA.fullmatch(commit) or any(
        os.environ.get(k) != v for k, v in expected.items()
    ):
        raise ValueError("UNTRUSTED_VERIFIER_SOURCE")
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True
    ).strip()
    if actual != commit:
        raise ValueError("UNTRUSTED_VERIFIER_CHECKOUT")


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("GitHub evidence timestamp must include timezone")
    return result


def newest(rows: list[dict[str, Any]], commit: str) -> dict[str, Any]:
    eligible = [
        row
        for row in rows
        if row.get("path") == offline.DAY38_PATH
        and row.get("event") == "push"
        and row.get("head_branch") == "main"
        and row.get("head_sha") == commit
    ]
    if not eligible:
        raise ValueError("MISSING_SECURITY_PROOF")
    for row in eligible:
        if (
            row.get("name") != offline.DAY38_NAME
            or row.get("repository", {}).get("full_name") != offline.REPO
            or row.get("head_repository", {}).get("full_name") != offline.REPO
            or type(row.get("id")) is not int
            or row["id"] < 1
            or type(row.get("run_attempt")) is not int
            or row["run_attempt"] < 1
        ):
            raise ValueError("Invalid Day38 repository, workflow or attempt identity")
    run = max(
        eligible, key=lambda row: (timestamp(row["created_at"]), row["id"], row["run_attempt"])
    )
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise ValueError("UPSTREAM_FAILED")
    return run


def run_identity(run: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(
        run[k]
        for k in (
            "id",
            "run_attempt",
            "head_sha",
            "workflow_id",
            "event",
            "head_branch",
            "path",
            "status",
            "conclusion",
            "run_started_at",
        )
    )


class AttemptEvidence(offline.GitHub):
    def __init__(self, token: str, run: dict[str, Any]):
        super().__init__(token)
        self.run = run

    def jobs(self, run_id: int) -> list[dict[str, Any]]:
        if run_id != self.run["id"]:
            raise ValueError("ATTEMPT_REPLAY")
        attempt = self.run["run_attempt"]
        data = self.get(f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        rows = data["jobs"]
        if (
            not isinstance(rows, list)
            or data["total_count"] != len(rows)
            or len(rows) > 100
            or any(j.get("run_id") != run_id or j.get("run_attempt") != attempt for j in rows)
        ):
            raise ValueError("ATTEMPT_REPLAY or incomplete GitHub job inventory")
        return rows

    def artifacts(self, run_id: int) -> list[dict[str, Any]]:
        if run_id != self.run["id"]:
            raise ValueError("ATTEMPT_REPLAY")
        suffix = f"-{run_id}-{self.run['run_attempt']}"
        current = [a for a in super().artifacts(run_id) if a["name"].endswith(suffix)]
        for artifact in current:
            self.require_artifact_owner(artifact)
        return sorted(current, key=lambda a: a["id"])

    def require_artifact_owner(self, artifact: dict[str, Any]) -> None:
        owner = artifact.get("workflow_run") or {}
        if (
            owner.get("id") != self.run["id"]
            or owner.get("head_sha") != self.run["head_sha"]
            or timestamp(artifact["created_at"]) < timestamp(self.run["run_started_at"])
        ):
            raise ValueError("ATTEMPT_REPLAY or cross-source artifact")


def require_environment_protection(api: offline.GitHub) -> None:
    for name in ENVIRONMENTS:
        path = f"environments/{name}"
        environment = api.get(path)
        reviewers = [
            rule for rule in environment["protection_rules"] if rule["type"] == "required_reviewers"
        ]
        branches = api.get(path + "/deployment-branch-policies?per_page=100")
        if (
            environment.get("can_admins_bypass") is not False
            or environment.get("deployment_branch_policy")
            != {"protected_branches": False, "custom_branch_policies": True}
            or len(reviewers) != 1
            or reviewers[0].get("prevent_self_review") is not True
            or not reviewers[0].get("reviewers")
            or branches["total_count"] != 1
            or [(b.get("name"), b.get("type")) for b in branches["branch_policies"]]
            != [("main", "branch")]
        ):
            raise ValueError("Unverified protected-main approval environment: " + name)


def verify_runtime(commit: str, run: dict[str, Any]) -> dict[str, Any]:
    """Require the current Runtime gate and sealed security evidence."""
    if (
        run.get("path") != RUNTIME_PATH
        or run.get("name") != offline.WORKFLOWS[RUNTIME_PATH]
        or run.get("head_sha") != commit
        or run.get("repository", {}).get("full_name") != offline.REPO
        or run.get("head_repository", {}).get("full_name") != offline.REPO
    ):
        raise ValueError("Runtime security source mismatch")
    client = AttemptEvidence(os.environ["GH_TOKEN"], run)
    run_id, attempt = run["id"], run["run_attempt"]
    current = client.get(f"actions/runs/{run_id}/attempts/{attempt}")
    if run_identity(current) != run_identity(run):
        raise ValueError("Runtime ATTEMPT_REPLAY")
    offline.require_final_job(client, RUNTIME_PATH, run)
    artifacts = offline.GitHub.artifacts(client, run_id)
    entry = offline.locate_artifact(artifacts, "runtime-verified-evidence", run)
    client.require_artifact_owner(entry)
    provenance, members = offline.read_proof(
        client, run, [entry], "runtime-verified-evidence", "runtime-evidence"
    )
    proof = offline.strict_json(members["day35-acceptance.json"])
    hashes = proof["proofs"]
    if (
        provenance is None
        or provenance["day31_commit"] != commit
        or proof.get("decision") != "READY_FOR_LOCAL_REVIEW"
        or proof.get("ci_verified") is not True
        or proof.get("release_authorized") is not False
        or proof.get("real_aws_verified") is not False
        or proof.get("physical_boot_verified") is not False
        or proof["provenance"]["commit"] != commit
        or proof["provenance"]["run_id"] != f"{run_id}:{attempt}"
        or set(hashes) != {"day35-runtime-faults.xml", "day34-acceptance.json"}
        or any(offline.digest(members[name]) != digest for name, digest in hashes.items())
    ):
        raise ValueError("MISSING_SECURITY_PROOF or Runtime security evidence mismatch")
    return {"run_id": run_id, "run_attempt": attempt, "id": entry["id"], "digest": entry["digest"]}


def verify(commit: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    require_trusted_source(commit)
    run = newest(rows, commit)
    client = AttemptEvidence(os.environ.get("GH_TOKEN", ""), run)
    run_id, attempt = run["id"], run["run_attempt"]
    current = client.get(f"actions/runs/{run_id}/attempts/{attempt}")
    if run_identity(current) != run_identity(run):
        raise ValueError("ATTEMPT_REPLAY")
    artifacts = client.artifacts(run_id)
    proof = offline.verify_day38_offline(client, [run], commit, "push", "main", commit)
    if (
        proof.get("candidate_sha") != commit
        or proof.get("run_id") != run_id
        or proof.get("run_attempt") != attempt
        or proof.get("decision") != "OFFLINE_AUDIT_PASS"
    ):
        raise ValueError("COMMIT_MISMATCH or ATTEMPT_REPLAY")
    require_environment_protection(client)
    fresh = client.get(f"actions/runs?head_sha={commit}&per_page=100")
    if fresh["total_count"] != len(fresh["workflow_runs"]) or fresh["total_count"] > 100:
        raise ValueError("Incomplete latest workflow inventory")
    if run_identity(newest(fresh["workflow_runs"], commit)) != run_identity(run):
        raise ValueError("Latest Day38 run changed during verification")
    if client.get("branches/main")["commit"]["sha"] != commit:
        raise ValueError("COMMIT_MISMATCH")
    if client.artifacts(run_id) != artifacts:
        raise ValueError("ARTIFACT_TAMPERED or artifact inventory changed")
    return {
        "decision": "DAY39_SECURITY_PASS",
        "verifier_sha": commit,
        "candidate_sha": commit,
        "day38_run_id": run_id,
        "day38_attempt": attempt,
        "artifacts": [{"id": a["id"], "name": a["name"], "digest": a["digest"]} for a in artifacts],
        "day38": proof,
        "aws_authorized": False,
        "production_authorized": False,
    }
