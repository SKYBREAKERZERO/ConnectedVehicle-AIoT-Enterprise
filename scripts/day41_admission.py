"""Independently inspect protected-main evidence; never grant rotation authority."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.error import URLError

from scripts import day38_readiness as gh
from scripts.day39_trusted_verifier import AttemptEvidence, newest, run_identity, timestamp
from scripts.day40_runtime_evidence import REPORTS, SUITES
from scripts.iac.day31_evidence import source_digest, xml_cases

PATH = ".github/workflows/day41-staging-rotation.yml"
DAY40 = ".github/workflows/day40-runtime-security.yml"
ENVIRONMENT = "aws-staging-rotation"
JOBS = {
    "01 Event-bound candidate and baseline",
    "02 Full Python quality and release policy",
    "03 PostgreSQL rotation and rollback",
    "04 Redis TLS, token overlap and client replacement",
    "05 Native Terraform validation / ota-staging",
    "05 Native Terraform validation / ota-staging-identity",
    "05 Native Terraform validation / ota-staging-foundation",
    "06 Checkov deployment source and CI fixture",
    "07 Independently verify rotation and IaC evidence",
    "08 Day40 acceptance and AWS release boundary",
}


def latest_day40(rows: list[dict[str, Any]], sha: str) -> dict[str, Any]:
    eligible = [
        row
        for row in rows
        if row.get("path") == DAY40
        and row.get("head_sha") == sha
        and row.get("event") == "push"
        and row.get("head_branch") == "main"
    ]
    gh.require(bool(eligible), "MISSING_MAIN_DAY40")
    for row in eligible:
        gh.require(
            row.get("name") == "Day40 Runtime Security Closed Loop"
            and row["repository"]["full_name"] == gh.REPO
            and row["head_repository"]["full_name"] == gh.REPO
            and all(type(row.get(k)) is int and row[k] > 0 for k in ("id", "run_attempt")),
            "INVALID_DAY40_RUN",
        )
    run = max(eligible, key=lambda r: (timestamp(r["created_at"]), r["id"], r["run_attempt"]))
    gh.require(
        run["status"] == "completed" and run["conclusion"] == "success", "LATEST_DAY40_FAILED"
    )
    return run


def require_day40_jobs(jobs: list[dict[str, Any]], sha: str) -> None:
    gh.require(
        len(jobs) == len(JOBS)
        and {job["name"] for job in jobs} == JOBS
        and all(
            job["head_sha"] == sha
            and job["status"] == "completed"
            and job["conclusion"] == "success"
            for job in jobs
        ),
        "DAY40_JOB_INVENTORY_OR_RESULT_MISMATCH",
    )


def verify_day40(token: str, run: dict[str, Any], sha: str) -> dict[str, Any]:
    api = AttemptEvidence(token, run)
    run_id, attempt = run["id"], run["run_attempt"]
    gh.require(
        run_identity(api.get(f"actions/runs/{run_id}/attempts/{attempt}")) == run_identity(run),
        "DAY40_ATTEMPT_REPLAY",
    )
    require_day40_jobs(api.jobs(run_id), sha)
    artifacts = api.artifacts(run_id)

    def read(name: str) -> tuple[dict[str, Any], dict[str, bytes]]:
        entry = gh.locate_artifact(artifacts, f"day40-{name}-{run_id}-{attempt}", run)
        files = gh.check_zip(gh.download_artifact(entry["id"], token, entry["digest"]))
        return entry, files

    entry, files = read("decision")
    decision = gh.json_artifact(files, "decision.json")
    agg_entry, aggregate = read("proof-aggregate")
    expected = {
        "day31_commit": sha,
        "day31_run_id": f"{run_id}:{attempt}",
        "day31_source_sha256": source_digest(),
    }
    provenance, _ = gh.verify_sealed(aggregate, "aggregate", run)
    agg = gh.strict_json(aggregate["aggregate.json"])
    gh.require(
        decision["provenance"] == agg["provenance"] == provenance == expected
        and decision["local_decision"] == "ROTATION_TESTED_LOCAL"
        and decision["aws_staging_decision"] == "BLOCKED"
        and all(
            decision[k] is False
            for k in ("aws_rotation_verified", "release_authorized", "production_authorized")
        )
        and decision["aggregate_sha256"] == gh.digest(aggregate["aggregate.json"])
        and set(agg["reports"]) == set(REPORTS),
        "DAY40_EVIDENCE_MISMATCH",
    )
    verified = [entry, agg_entry]
    for stage, name in REPORTS.items():
        artifact, report = read(f"proof-{stage}")
        observed, _ = gh.verify_sealed(report, stage, run)
        gh.require(
            observed == expected
            and set(report) == {"manifest.json", name}
            and gh.digest(report[name]) == agg["reports"][stage],
            "DAY40_REPORT_MISMATCH",
        )
        if stage in SUITES:
            xml_cases(report[name], SUITES[stage], {}, exact=stage != "quality")
        elif stage == "scan":
            gh.require(
                gh.strict_json(report[name])
                == {
                    "status": "passed",
                    "phase": "security",
                    "security_scan": "passed",
                    "scanned_sources": 2,
                },
                "DAY40_SCAN_FAILED",
            )
        else:
            validation = gh.strict_json(report[name])
            gh.require(
                validation.get("valid") is True and validation.get("error_count") == 0,
                "DAY40_TERRAFORM_VALIDATION_FAILED",
            )
        verified.append(artifact)
    gh.require(api.artifacts(run_id) == artifacts, "DAY40_ARTIFACT_INVENTORY_CHANGED")
    return {
        "run_id": run_id,
        "attempt": attempt,
        "artifacts": [{"id": a["id"], "digest": a["digest"]} for a in verified],
    }


def require_environment(api: gh.GitHub) -> None:
    path = f"environments/{ENVIRONMENT}"
    environment = api.get(path)
    branches = api.get(path + "/deployment-branch-policies?per_page=100")
    reviewers = [r for r in environment["protection_rules"] if r["type"] == "required_reviewers"]
    gh.require(
        environment.get("can_admins_bypass") is False
        and environment.get("deployment_branch_policy")
        == {"protected_branches": False, "custom_branch_policies": True}
        and len(reviewers) == 1
        and reviewers[0].get("prevent_self_review") is True
        and bool(reviewers[0].get("reviewers"))
        and branches["total_count"] == 1
        and [(b["name"], b["type"]) for b in branches["branch_policies"]] == [("main", "branch")],
        "STAGING_ENVIRONMENT_NOT_PROTECTED",
    )


def require_source(sha: str) -> None:
    gh.require(bool(gh.SHA.fullmatch(sha)), "INVALID_CANDIDATE")
    expected = {
        "GITHUB_REPOSITORY": gh.REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{gh.REPO}/{PATH}@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": sha,
        "GITHUB_REF_PROTECTED": "true",
    }
    gh.require(all(os.environ.get(k) == v for k, v in expected.items()), "UNTRUSTED_SOURCE")
    gh.require(
        subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == sha,
        "CHECKOUT_MISMATCH",
    )


def collect(sha: str, token: str, receipt: dict[str, Any]) -> None:
    require_source(sha)
    api = gh.GitHub(token)

    def require_main() -> None:
        main = api.get("branches/main")
        gh.require(main["protected"] is True and main["commit"]["sha"] == sha, "MAIN_CHANGED")
        gh.verify_main_ruleset(api.get(f"rulesets/{gh.MAIN_RULESET_ID}"))

    require_main()
    rows = api.runs(sha)
    run = latest_day40(rows, sha)
    receipt["day40"] = verify_day40(token, run, sha)
    day38 = newest(rows, sha)
    client = AttemptEvidence(token, day38)
    proof = gh.verify_day38_offline(client, [day38], sha, "push", "main", sha)
    gh.require(
        proof["decision"] == "OFFLINE_AUDIT_PASS"
        and proof["candidate_sha"] == sha
        and proof["run_id"] == day38["id"]
        and proof["run_attempt"] == day38["run_attempt"],
        "DAY38_EVIDENCE_MISMATCH",
    )
    receipt["day38"] = {"run_id": day38["id"], "attempt": day38["run_attempt"]}
    require_environment(api)
    fresh = api.runs(sha)
    gh.require(
        run_identity(latest_day40(fresh, sha)) == run_identity(run)
        and run_identity(newest(fresh, sha)) == run_identity(day38),
        "UPSTREAM_ATTEMPT_CHANGED",
    )
    require_main()
    receipt["github_prerequisites_verified"] = True


def main() -> int:
    sha = os.environ.get("GITHUB_SHA", "")
    receipt: dict[str, Any] = {
        "candidate_sha": sha,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "decision": "BLOCKED",
        "github_prerequisites_verified": False,
        "aws_rotation_verified": False,
        "production_authorized": False,
        "release_authorized": False,
    }
    try:
        collect(sha, os.environ["GH_TOKEN"], receipt)
        receipt["reason"] = "LIVE_EXECUTOR_AND_INDEPENDENT_AWS_RECEIPTS_NOT_INSTALLED"
    except (ValueError, KeyError, TypeError, OSError, URLError, subprocess.SubprocessError):
        receipt["reason"] = "TRUSTED_PREREQUISITES_NOT_VERIFIED"
    Path("day41-admission.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
