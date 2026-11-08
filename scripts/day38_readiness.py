"""Day38 read-only release-readiness verifier (never authorizes AWS deployment).

On workflow_run the script is checked out from protected main. It treats every
upstream workflow and uploaded artifact as untrusted data and verifies source,
run, attempt, identity, checksums, and explicit non-deployment decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
API = f"https://api.github.com/repos/{REPO}/"
MAIN_RULESET_ID = 24828733
SHA = re.compile(r"[a-f0-9]{40}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-z0-9_-]+\.(json|xml)\Z")
MAX_ARCHIVE = 16_000_000
MAX_MEMBER = 6_000_000
MAX_TOTAL = 35_000_000
MAX_RUNS = 500
WORKFLOWS = {
    ".github/workflows/ci.yml": "IaC quality gates",
    ".github/workflows/runtime.yml": "Runtime quality gates",
    ".github/workflows/day34.yml": "Day34 full OTA acceptance",
    ".github/workflows/day35.yml": "Day35 full OTA acceptance",
    ".github/workflows/day37-aws-staging.yml": "Day37 AWS Staging enterprise release (fail closed)",
    ".github/workflows/day31-trust-boundary.yml": "Day31 trust boundary",
    ".github/workflows/ci-fault-matrix.yml": "CI isolation fault matrix",
}
DAY38_PATH = ".github/workflows/day38-release-readiness.yml"
DAY38_NAME = "Day38 enterprise IaC release readiness"
DAY38_OFFLINE_JOB = "Day38 offline Terraform security and contract audit"
DAY38_GATE_JOB = "Day38 offline audit gate (not AWS release)"
DAY38_AGGREGATE_STAGE = "day38-aggregate"
DAY38_REQUIRED_STAGES = (
    "day38-source",
    "day38-dependencies",
    "day38-python-quality",
    "day38-terraform-format",
    "day38-root-ota-staging",
    "day38-root-ota-staging-foundation",
    "day38-root-ota-staging-identity",
    "day38-module-foundation",
    "day38-module-ota",
    "day38-module-governance",
    "day38-module-roots",
    "day38-security",
    "day38-policy-tests",
    "day38-trust-tests",
    "day38-recovery-tests",
    "day38-day37-tests",
    "day38-database-tests",
    "day38-ota-tests",
    "day38-fault-probes",
    "day38-workflow-contracts",
    "day38-supply-tests",
    "day38-state-tests",
)
DAY38_REQUIRED_JOB_NAMES = (
    "Day38 immutable source intake",
    "Day38 source provenance and workflow trust",
    "Day38 pinned dependency closure and compiler",
    "Day38 Python Ruff, formatting and strict typing",
    "Day38 Terraform global fmt and lock inventory",
    *(
        f"Day38 static AWS Terraform root ({root})"
        for root in ("ota-staging", "ota-staging-foundation", "ota-staging-identity")
    ),
    *(
        f"Day38 Terraform contract group ({group})"
        for group in ("foundation", "ota", "governance", "roots")
    ),
    "Day38 Checkov whole-source security gate",
    "Day38 Checkov and Terraform policy regressions",
    "Day38 GitHub trust and provenance regressions",
    "Day38 rollback and drift recovery contracts",
    "Day38 Day37 AWS staging release contracts",
    "Day38 database roles, grants and RLS policy",
    "Day38 OTA authorization and recovery tests",
    "Day38 adversarial evidence fault-injection probes",
    "Day38 workflow triggers, privileges and controls",
    "Day38 release supply chain and evidence policy",
    "Day38 state locking and isolation contracts",
    "Day38 cross-runner evidence aggregation",
)
FAULT_SCENARIOS = ("failure", "skipped", "missing-artifact", "tamper", "old-attempt")
FAULT_GRAPHS = ("iac", "runtime")
PR_ONLY = {
    ".github/workflows/day31-trust-boundary.yml",
    ".github/workflows/ci-fault-matrix.yml",
}
FINAL_JOBS = {
    ".github/workflows/ci.yml": "IaC quality gate",
    ".github/workflows/runtime.yml": "Runtime quality gate",
    ".github/workflows/day34.yml": "Day34 full acceptance gate",
    ".github/workflows/day35.yml": "Day35 full acceptance gate",
    ".github/workflows/day37-aws-staging.yml": (
        "10 Final evidence decision (deploy requires zero-drift closure)"
    ),
}


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("duplicate JSON key")
        obj[k] = v
    return obj


def strict_json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MEMBER:
        raise ValueError("oversized JSON")
    obj = json.loads(
        data,
        object_pairs_hook=unique_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be an object")
    return obj


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_url(url: str, *, token: str | None, max_bytes: int = MAX_ARCHIVE) -> bytes:
    headers = {"User-Agent": "cv-day38-readiness", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(max_bytes + 1)
    require(len(raw) <= max_bytes, "remote content exceeds bounded size")
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def download_artifact(artifact_id: int, token: str, expected_zip_hash: str) -> bytes:
    """Use GitHub's authorized redirect, then fetch signed URL WITHOUT bearer token."""
    require(isinstance(artifact_id, int) and artifact_id > 0, "invalid artifact ID")
    req = urllib.request.Request(
        API + f"actions/artifacts/{artifact_id}/zip",
        headers={"Authorization": "Bearer " + token, "User-Agent": "cv-day38-readiness"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(req, timeout=15)
        raise ValueError("GitHub artifact API did not return a download redirect")
    except urllib.error.HTTPError as exc:
        if exc.code not in (302, 303, 307):
            raise ValueError(f"GitHub artifact download denied ({exc.code})") from None
        location = exc.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    host = (parsed.hostname or "").lower()
    permitted = (
        host.endswith(".blob.core.windows.net")
        or host.endswith(".actions.githubusercontent.com")
        or host.endswith(".githubusercontent.com")
    )
    require(
        parsed.scheme == "https" and permitted and not parsed.username and not parsed.password,
        "untrusted artifact redirect endpoint",
    )
    raw = fetch_url(location, token=None)
    require(HASH.fullmatch(expected_zip_hash) is not None, "missing artifact ZIP digest")
    require(digest(raw) == expected_zip_hash, "GitHub artifact ZIP digest mismatch")
    return raw


def check_zip(raw: bytes) -> dict[str, bytes]:
    """Never extract untrusted ZIP files or execute anything in them."""
    require(len(raw) <= MAX_ARCHIVE, "oversized artifact archive")
    result: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.infolist()
        require(0 < len(names) <= 120, "unexpected ZIP member count")
        for meta in names:
            name = meta.filename
            require(
                not meta.is_dir() and (meta.external_attr >> 16 & 0o170000 != 0o120000),
                "artifact symlink/directory rejected",
            )
            require(
                (NAME.fullmatch(name) is not None or name == "manifest.json")
                and name not in result,
                "unsafe or duplicate artifact member",
            )
            require(meta.file_size <= MAX_MEMBER, "oversized artifact member")
            total += meta.file_size
            require(total <= MAX_TOTAL, "oversized expanded evidence")
            data = archive.read(meta)
            require(len(data) == meta.file_size, "truncated artifact member")
            result[name] = data
    return result


def verify_sealed(
    files: dict[str, bytes], stage: str, run: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, bytes]]:
    require("manifest.json" in files, "missing manifest.json")
    m = strict_json(files["manifest.json"])
    require(
        set(m) == {"version", "stage", "provenance", "files"}
        and type(m["version"]) is int
        and m["version"] == 1
        and m["stage"] == stage,
        "unknown sealed manifest schema",
    )
    proof = m["files"]
    require(
        isinstance(proof, dict) and bool(proof) and set(files) == set(proof) | {"manifest.json"},
        "missing/extra evidence members",
    )
    for name, value in proof.items():
        require(
            NAME.fullmatch(name) is not None
            and isinstance(value, str)
            and HASH.fullmatch(value) is not None
            and digest(files[name]) == value,
            "sealed file hash mismatch",
        )
    p = m["provenance"]
    require(
        isinstance(p, dict) and set(p) == {"day31_commit", "day31_run_id", "day31_source_sha256"},
        "unknown provenance schema",
    )
    require(
        SHA.fullmatch(p["day31_commit"]) is not None
        and p["day31_run_id"] == f"{run['id']}:{run['run_attempt']}"
        and HASH.fullmatch(p["day31_source_sha256"]) is not None,
        "manifest commit/run/attempt mismatch",
    )
    return p, files


def json_artifact(files: dict[str, bytes], expected: str) -> dict[str, Any]:
    require(set(files) == {expected}, "unexpected artifact members")
    return strict_json(files[expected])


class GitHub:
    def __init__(self, token: str):
        require(bool(token), "GH_TOKEN is required")
        self.token = token

    def get(self, path: str) -> dict[str, Any]:
        require(not path.startswith("/") and ".." not in path, "unsafe API path")
        return strict_json(fetch_url(API + path, token=self.token, max_bytes=MAX_MEMBER))

    def runs(self, candidate: str) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        for page in range(1, 6):
            data = self.get(f"actions/runs?head_sha={candidate}&per_page=100&page={page}")
            count = data.get("total_count")
            require(type(count) is int and 0 <= count <= MAX_RUNS, "unbounded workflow history")
            rows = data.get("workflow_runs")
            require(isinstance(rows, list), "invalid GitHub workflow run listing")
            collected.extend(rows)
            if len(collected) >= count:
                break
        require(len(collected) <= MAX_RUNS, "unexpected workflow pagination")
        return collected

    def jobs(self, run_id: int) -> list[dict[str, Any]]:
        data = self.get(f"actions/runs/{run_id}/jobs?per_page=100")
        rows = data.get("jobs")
        require(
            type(data.get("total_count")) is int
            and 0 <= data["total_count"] <= 100
            and isinstance(rows, list)
            and len(rows) == data["total_count"],
            "job pagination or schema ambiguity",
        )
        return rows

    def artifacts(self, run_id: int) -> list[dict[str, Any]]:
        data = self.get(f"actions/runs/{run_id}/artifacts?per_page=100")
        rows = data.get("artifacts")
        require(
            type(data.get("total_count")) is int
            and 0 <= data["total_count"] <= 100
            and isinstance(rows, list)
            and len(rows) == data["total_count"],
            "artifact pagination or schema ambiguity",
        )
        return rows


def verify_main_ruleset(ruleset: dict[str, Any]) -> None:
    """Do not promote a result if protected-main rules are unverified or weakened."""
    require(
        ruleset.get("target") == "branch"
        and ruleset.get("enforcement") == "active"
        and ruleset.get("conditions")
        == {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "main branch ruleset not actively enforced",
    )
    require(
        "bypass_actors" in ruleset and ruleset["bypass_actors"] == [],
        "unverified/active main ruleset bypass",
    )
    rules = ruleset.get("rules")
    require(
        isinstance(rules, list) and all(isinstance(r, dict) for r in rules),
        "ruleset protection rules missing",
    )
    kinds = {r.get("type") for r in rules if isinstance(r, dict)}
    require(
        {"deletion", "non_fast_forward"} <= kinds,
        "branch deletion/non-fast-forward protection missing",
    )
    approval = [r.get("parameters", {}) for r in rules if r.get("type") == "pull_request"]
    checks = [r.get("parameters", {}) for r in rules if r.get("type") == "required_status_checks"]
    require(
        len(approval) == 1 and len(checks) == 1, "branch approvals or required checks ambiguous"
    )
    p, c = approval[0], checks[0]
    require(isinstance(p, dict) and isinstance(c, dict), "invalid branch governance parameters")
    require(
        type(p.get("required_approving_review_count")) is int
        and p["required_approving_review_count"] >= 1
        and all(
            p.get(k) is True
            for k in (
                "dismiss_stale_reviews_on_push",
                "require_last_push_approval",
                "required_review_thread_resolution",
            )
        ),
        "independent approvals/review policy weakened",
    )
    required = c.get("required_status_checks")
    require(
        isinstance(required, list) and all(isinstance(x, dict) for x in required),
        "invalid required status rules",
    )
    actual = {(x.get("context"), x.get("integration_id")) for x in required}
    require(
        c.get("strict_required_status_checks_policy") is True
        and c.get("do_not_enforce_on_create") is False
        and actual == {("Runtime quality gate", 15368), ("IaC quality gate", 15368)},
        "main required statuses changed",
    )


def selected_runs(
    rows: list[dict[str, Any]], candidate: str, event: str, branch: str
) -> dict[str, dict[str, Any]]:
    require(
        SHA.fullmatch(candidate) is not None and event in {"push", "pull_request"},
        "invalid source event/commit",
    )
    expected = set(WORKFLOWS) if event == "pull_request" else set(WORKFLOWS) - PR_ONLY
    matching: dict[str, list[dict[str, Any]]] = {k: [] for k in expected}
    for r in rows:
        path = str(r.get("path", "")).split("@", 1)[0]
        if (
            path in expected
            and r.get("head_sha") == candidate
            and r.get("event") == event
            and r.get("head_branch") == branch
        ):
            require(r.get("name") == WORKFLOWS[path], "workflow name/path mismatch")
            matching[path].append(r)
    chosen: dict[str, dict[str, Any]] = {}
    for path, options in matching.items():
        require(bool(options), "missing required workflow: " + path)
        # An older successful run never overrides a newer failed/pending run.
        for item in options:
            started = item.get("run_started_at")
            require(
                isinstance(started, str) and started.endswith("Z") and len(started) <= 40,
                "run start timestamp missing or malformed",
            )
            try:
                datetime.fromisoformat(started.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("invalid workflow run timestamp") from exc
        run = max(options, key=lambda x: (x["run_started_at"], x["id"], x["run_attempt"]))
        require(
            run.get("status") == "completed" and run.get("conclusion") == "success",
            "required workflow not successful: " + path,
        )
        require(
            type(run.get("run_attempt")) is int
            and run["run_attempt"] >= 1
            and type(run.get("id")) is int
            and run["id"] > 0,
            "invalid run/attempt",
        )
        chosen[path] = run
    return chosen


def locate_artifact(rows: list[dict[str, Any]], name: str, run: dict[str, Any]) -> dict[str, Any]:
    found = [a for a in rows if a.get("name") == name]
    require(len(found) == 1, "missing/duplicate required artifact: " + name)
    a = found[0]
    sha = str(a.get("digest", ""))
    require(
        a.get("expired") is False
        and sha.startswith("sha256:")
        and HASH.fullmatch(sha[7:]) is not None
        and type(a.get("id")) is int
        and type(a.get("size_in_bytes")) is int
        and 0 < a["size_in_bytes"] <= MAX_ARCHIVE,
        "expired/malformed artifact evidence: " + name,
    )
    workflow_run = a.get("workflow_run", {})
    if workflow_run:
        require(
            workflow_run.get("id") == run["id"] and workflow_run.get("head_sha") == run["head_sha"],
            "cross-run artifact identity",
        )
    return a


def read_proof(
    api: GitHub,
    run: dict[str, Any],
    artifacts: list[dict[str, Any]],
    name: str,
    stage: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, bytes]]:
    entry = locate_artifact(artifacts, name, run)
    data = check_zip(download_artifact(entry["id"], api.token, entry["digest"][7:]))
    if stage:
        return verify_sealed(data, stage, run)
    return None, data


def validate_baseline(
    b: dict[str, Any], run: dict[str, Any], head: str, event: str, branch: str
) -> str:
    require(
        b.get("repository") == REPO
        and b.get("event") == event
        and b.get("run_id") == run["id"]
        and b.get("run_attempt") == run["run_attempt"],
        "baseline repository/event/run identity mismatch",
    )
    candidate = b.get("candidate_sha")
    require(
        isinstance(candidate, str) and SHA.fullmatch(candidate) is not None,
        "malformed baseline candidate",
    )
    if event == "push":
        require(candidate == head and b.get("ref") == "refs/heads/main", "wrong main candidate")
    else:
        require(
            b.get("pr_head_sha") == head
            and str(b.get("ref", "")).startswith("refs/pull/")
            and b.get("pr_number") is not None,
            "wrong PR head/candidate binding",
        )
    require(run["head_branch"] == branch, "baseline branch mismatch")
    return candidate


def require_final_job(api: GitHub, path: str, run: dict[str, Any]) -> None:
    if path not in FINAL_JOBS:
        return
    wanted = FINAL_JOBS[path]
    jobs = api.jobs(run["id"])
    found = [x for x in jobs if x.get("name") == wanted]
    require(
        len(found) == 1 and found[0].get("conclusion") == "success",
        "missing or failed mandatory final job: " + wanted,
    )
    if path == ".github/workflows/day37-aws-staging.yml":
        source = [x for x in jobs if x.get("name", "").startswith("01 Static contracts")]
        require(
            len(source) == 1 and source[0].get("conclusion") == "success",
            "Day37 audit source unverified",
        )
        require(
            all(
                x.get("conclusion") == "skipped" for x in jobs if x not in source and x not in found
            ),
            "Day37 audit unexpectedly executed privileged AWS jobs",
        )


def verify_fault_job_matrix(jobs: list[dict[str, Any]]) -> None:
    """Cross-check each untrusted fault receipt against actual GitHub job results.

    continue-on-error intentionally allows the matrix workflow's oracle to
    succeed despite expected failing producer/consumer jobs. A GREEN oracle
    alone is insufficient: all 30 native job conclusions must be observed.
    """
    expected: dict[str, str] = {}
    for graph in FAULT_GRAPHS:
        for scenario in FAULT_SCENARIOS:
            prefix = f"fault ({graph}, {scenario}) / "
            expected[prefix + "producer"] = (
                "skipped"
                if scenario == "skipped"
                else "failure"
                if scenario == "failure"
                else "success"
            )
            expected[prefix + "consumer"] = "failure"
            expected[prefix + "oracle"] = "success"
    actual = {str(j.get("name")): j for j in jobs}
    require(
        len(actual) == len(jobs) and set(actual) == set(expected),
        "missing, duplicated or unexpected fault matrix jobs",
    )
    for name, conclusion in expected.items():
        job = actual[name]
        require(
            job.get("conclusion") == conclusion and job.get("status") == "completed",
            "GitHub fault job not in expected verified state: " + name,
        )


def verify_fault_receipt(
    receipt: dict[str, Any],
    run: dict[str, Any],
    graph: str,
    scenario: str,
    candidate: str,
) -> None:
    """Check real fault-oracle outcomes from the existing CI isolation matrix.

    The matrix intentionally contains failing *steps* but successful oracle jobs.
    Its report schema is defined in scripts/iac/pipeline_fault_probe.py.
    Uploaded names, a 'success' workflow conclusion or asserted flags alone
    are not evidence of an expected failure being blocked.
    """
    require(graph in FAULT_GRAPHS and scenario in FAULT_SCENARIOS, "unrecognized fault oracle")
    attempt = run["run_attempt"]
    require(
        receipt.get("scope") == "isolated-actions-scheduler-and-artifact-probe"
        and receipt.get("graph") == graph
        and receipt.get("scenario") == scenario
        and receipt.get("commit") == candidate
        and str(receipt.get("run_id")) == str(run["id"])
        and type(receipt.get("attempt")) is int
        and receipt["attempt"] == attempt
        and receipt.get("deployment_authorized") is False
        and receipt.get("fault_blocked") is True
        and receipt.get("single_fault_isolated") is True,
        "fault oracle scope/provenance/deny result mismatch",
    )
    expected_history = "1" if scenario == "old-attempt" and attempt > 1 else None
    require(
        receipt.get("historical_input_attempt") == expected_history,
        "fault oracle historical attempt mismatch",
    )
    p_attempt = receipt.get("producer_attempt")
    if scenario == "skipped":
        require(p_attempt in {None, ""}, "skipped producer claims an attempt")
    else:
        require(str(p_attempt) == str(attempt), "foreign producer attempt")
    needs = receipt.get("observed_needs")
    require(
        isinstance(needs, dict)
        and set(needs) == {"producer", "consumer"}
        and all(isinstance(v, dict) for v in needs.values()),
        "fault oracle scheduler evidence missing",
    )
    producer, consumer = needs["producer"], needs["consumer"]
    p_outputs, c_outputs = producer.get("outputs"), consumer.get("outputs")
    require(
        isinstance(p_outputs, dict) and isinstance(c_outputs, dict),
        "fault oracle operation outputs missing",
    )
    step = (
        "guard"
        if scenario in {"failure", "skipped"}
        else "download"
        if scenario == "missing-artifact"
        else "verify"
    )
    required_producer = "skipped" if scenario == "skipped" else "success"
    require(
        producer.get("result") == required_producer
        and consumer.get("result") == "success"
        and c_outputs.get(step) == "failure"
        and (
            scenario == "skipped"
            or p_outputs.get("operation") == ("failure" if scenario == "failure" else "success")
        )
        and (step == "guard" or c_outputs.get("guard") == "success")
        and (step != "verify" or c_outputs.get("download") == "success"),
        "fault oracle did not block at required boundary",
    )
    require(
        scenario == "skipped" or str(p_outputs.get("attempt")) == str(attempt),
        "fault scheduler producer attempt differs",
    )


def verify_enterprise_offline_artifacts(
    api: GitHub, run: dict[str, Any], artifacts: list[dict[str, Any]], candidate: str
) -> dict[str, Any]:
    """Independently authenticate full Day38 stage matrix and final receipt.

    A successful umbrella job or unverified CI artifact name is insufficient.
    The verified aggregate is source/run/attempt-bound, and every mandatory
    nested-stage receipt must have a valid SHA256 reference.
    """
    provenance, content = read_proof(
        api,
        run,
        artifacts,
        f"day38-aggregate-{run['id']}-{run['run_attempt']}",
        DAY38_AGGREGATE_STAGE,
    )
    require(
        provenance is not None and provenance.get("day31_commit") == candidate,
        "Day38 aggregate source SHA differs from tested candidate",
    )
    require(
        set(content) == {"manifest.json", "aggregate.json"},
        "Day38 aggregate manifest has unexpected members",
    )
    report = strict_json(content["aggregate.json"])
    binding = {
        "repository": REPO,
        "candidate_sha": candidate,
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
    }
    require(
        report.get("schema_version") == "day38.aggregate.v1"
        and report.get("decision") == "OFFLINE_STAGE_EVIDENCE_VERIFIED"
        and report.get("source") == binding
        and report.get("mandatory_stages") == list(DAY38_REQUIRED_STAGES)
        and report.get("release_authorized") is False
        and report.get("aws_plan_or_apply_executed") is False,
        "Day38 aggregate missing stage identity or non-deployment decision",
    )
    stages = report.get("stages")
    require(
        isinstance(stages, dict) and set(stages) == set(DAY38_REQUIRED_STAGES),
        "Day38 mandatory stage set incomplete",
    )
    for stage in DAY38_REQUIRED_STAGES:
        info = stages[stage]
        require(
            isinstance(info, dict)
            and info.get("source") == binding
            and HASH.fullmatch(str(info.get("manifest_sha256", ""))) is not None
            and HASH.fullmatch(str(info.get("report_sha256", ""))) is not None,
            "Day38 stage hash or binding invalid: " + stage,
        )

    _, result_files = read_proof(
        api,
        run,
        artifacts,
        f"day38-final-{run['id']}-{run['run_attempt']}",
    )
    decision = json_artifact(result_files, "decision.json")
    require(
        decision.get("schema_version") == "day38.gate.v1"
        and decision.get("decision") == "OFFLINE_AUDIT_PASS"
        and decision.get("source") == binding
        and decision.get("aggregate_sha256") == digest(content["aggregate.json"])
        and decision.get("release_authorized") is False
        and decision.get("aws_authorized") is False,
        "Day38 final gate missing or not bound to verified aggregate",
    )
    return {
        "stage_count": len(stages),
        "aggregate_sha256": digest(content["aggregate.json"]),
        "final_gate": "OFFLINE_AUDIT_PASS",
    }


def verify_day38_offline(
    api: GitHub, rows: list[dict[str, Any]], head: str, event: str, branch: str, candidate: str
) -> dict[str, Any]:
    """Prove that the same tested candidate has actually passed Day38 offline.

    A workflow_run success cannot substitute for the PR's own security scan.
    The latest Day38 PR/push run, its real GitHub job status, and the content
    of its audit receipt must ALL pass before READY_FOR_STAGING_REVIEW.
    """
    eligible = [
        r
        for r in rows
        if str(r.get("path", "")).split("@", 1)[0] == DAY38_PATH
        and r.get("event") == event
        and r.get("head_sha") == head
        and r.get("head_branch") == branch
    ]
    require(eligible, "matching Day38 offline audit workflow is missing")
    require(all(r.get("name") == DAY38_NAME for r in eligible), "Day38 workflow path/name mismatch")
    run = max(
        eligible,
        key=lambda r: (
            str(r.get("run_started_at", "")),
            int(r.get("id", 0)),
            int(r.get("run_attempt", 0)),
        ),
    )
    require(
        run.get("conclusion") == "success"
        and run.get("status") == "completed"
        and type(run.get("id")) is int
        and run["id"] > 0
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] >= 1,
        "latest Day38 offline workflow did not succeed",
    )
    jobs = api.jobs(run["id"])
    for job_name in (DAY38_OFFLINE_JOB, DAY38_GATE_JOB):
        matching = [j for j in jobs if j.get("name") == job_name]
        require(
            len(matching) == 1 and matching[0].get("conclusion") == "success",
            "missing or unsuccessful Day38 offline job: " + job_name,
        )
    expected_names = set(DAY38_REQUIRED_JOB_NAMES)
    observed_names = [j.get("name") for j in jobs]
    require(
        all(observed_names.count(name) == 1 for name in expected_names),
        "Day38 mandatory independent source/security/evidence job missing or duplicated",
    )
    require(
        all(
            next(j for j in jobs if j.get("name") == name).get("conclusion") == "success"
            for name in expected_names
        ),
        "Day38 mandatory enterprise job failed, skipped or cancelled",
    )
    offline_jobs = [j for j in jobs if j.get("name") == DAY38_OFFLINE_JOB]
    required_steps = {
        "Bind event candidate and independent ancestor baseline",
        "Validate all Terraform formatting and each AWS-only root",
        "Run pinned offline IaC security gate (no waiver bypass)",
        "Regress trust, Checkov and Day38 fail-closed rules",
        "Emit audit receipt even for failures",
        "Upload untrusted read-only audit diagnostics",
    }
    steps = offline_jobs[0].get("steps")
    require(isinstance(steps, list), "Day38 offline executed step evidence missing")
    matches = [s for s in steps if isinstance(s, dict) and s.get("name") in required_steps]
    require(
        len(matches) == len(required_steps)
        and {s["name"] for s in matches} == required_steps
        and all(s.get("conclusion") == "success" for s in matches),
        "Day38 offline mandatory Terraform/Checkov step was not run successfully",
    )
    artifacts = api.artifacts(run["id"])
    _, members = read_proof(api, run, artifacts, f"day38-offline-{run['id']}-{run['run_attempt']}")
    require("day38-audit.json" in members, "Day38 offline receipt missing")
    record = strict_json(members["day38-audit.json"])
    require(
        record.get("schema_version") == "day38.v1"
        and record.get("decision") == "OFFLINE_AUDIT_PASS"
        and record.get("checks")
        == {
            "baseline": "success",
            "terraform": "success",
            "security": "success",
            "regression": "success",
        }
        and record.get("commit") == candidate
        and str(record.get("run_id")) == str(run["id"])
        and str(record.get("run_attempt")) == str(run["run_attempt"])
        and record.get("release_authorized") is False
        and record.get("real_aws_verified") is False,
        "Day38 offline audit content/source/authority mismatch",
    )
    enterprise = verify_enterprise_offline_artifacts(api, run, artifacts, candidate)
    return {
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "candidate_sha": candidate,
        "audit_sha256": digest(members["day38-audit.json"]),
        "decision": "OFFLINE_AUDIT_PASS",
        "enterprise": enterprise,
    }


def verify_existing(
    api: GitHub, runs: dict[str, dict[str, Any]], head: str, event: str, branch: str
) -> dict[str, Any]:
    for path, run in runs.items():
        require_final_job(api, path, run)

    iac = runs[".github/workflows/ci.yml"]
    runtime = runs[".github/workflows/runtime.yml"]
    day35 = runs[".github/workflows/day35.yml"]
    day37 = runs[".github/workflows/day37-aws-staging.yml"]
    artifacts = {path: api.artifacts(run["id"]) for path, run in runs.items()}
    candidates: list[str] = []
    provenance: list[dict[str, Any]] = []
    for path, run, baseline_name, baseline_stage, baseline_file, final_stage, final_name in [
        (
            ".github/workflows/ci.yml",
            iac,
            "iac-baseline-source",
            "iac-baseline",
            "day31-baseline.json",
            "iac-evidence",
            "iac-verified-evidence",
        ),
        (
            ".github/workflows/runtime.yml",
            runtime,
            "runtime-baseline-source",
            "runtime-baseline",
            "day31-runtime-baseline.json",
            "runtime-evidence",
            "runtime-verified-evidence",
        ),
    ]:
        b_prov, b_files = read_proof(api, run, artifacts[path], baseline_name, baseline_stage)
        baseline = strict_json(b_files[baseline_file])
        candidate = validate_baseline(baseline, run, head, event, branch)
        require(
            b_prov is not None and b_prov["day31_commit"] == candidate,
            "baseline sealed source differs",
        )
        f_prov, _ = read_proof(api, run, artifacts[path], final_name, final_stage)
        require(
            f_prov is not None
            and f_prov["day31_commit"] == candidate
            and f_prov["day31_source_sha256"] == b_prov["day31_source_sha256"],
            "final evidence source differs from baseline",
        )
        provenance.append(f_prov)
        candidates.append(candidate)
    require(
        len(set(candidates)) == 1 and len({p["day31_source_sha256"] for p in provenance}) == 1,
        "IaC and Runtime tested different sources",
    )
    candidate = candidates[0]

    _, d35_files = read_proof(
        api,
        day35,
        artifacts[".github/workflows/day35.yml"],
        f"day35-workflow-result-{day35['id']}-{day35['run_attempt']}",
    )
    d35 = json_artifact(d35_files, "day35-workflow-result.json")
    require(
        d35.get("decision") == "READY_FOR_LOCAL_REVIEW"
        and d35.get("ci_verified") is True
        and d35.get("release_authorized") is False
        and d35.get("real_aws_verified") is False
        and d35.get("production_apply_enabled") is False,
        "Day35 final acceptance missing/non-readonly",
    )
    require(
        validate_baseline(d35.get("baseline", {}), day35, head, event, branch) == candidate,
        "Day35 tested a different candidate",
    )

    _, d37_files = read_proof(
        api,
        day37,
        artifacts[".github/workflows/day37-aws-staging.yml"],
        f"day37-final-{day37['id']}-{day37['run_attempt']}",
    )
    # Day37 uploads .day37/final.json; upload-artifact stores its basename.
    d37 = json_artifact(d37_files, "final.json")
    require(
        d37.get("mode") == "audit"
        and d37.get("decision") == "READY_FOR_CONFIGURATION_REVIEW"
        and d37.get("commit") == candidate
        and str(d37.get("run_id")) == str(day37["id"])
        and str(d37.get("run_attempt")) == str(day37["run_attempt"])
        and d37.get("release_authorized") is False
        and d37.get("production_authorized") is False
        and d37.get("real_aws_verified") is False,
        "Day37 audit mode/provenance/authority mismatch",
    )

    if event == "pull_request":
        fault = runs[".github/workflows/ci-fault-matrix.yml"]
        fault_artifacts = artifacts[".github/workflows/ci-fault-matrix.yml"]
        verify_fault_job_matrix(api.jobs(fault["id"]))
        # Never infer a successful fault injection merely from its artifact name.
        # Every oracle's actual scheduler outcomes and denial must be authenticated.
        for graph in FAULT_GRAPHS:
            for scenario in FAULT_SCENARIOS:
                name = f"fault-result-{graph}-{scenario}-{fault['run_attempt']}"
                _, members = read_proof(api, fault, fault_artifacts, name)
                receipt = json_artifact(members, "fault-result.json")
                verify_fault_receipt(receipt, fault, graph, scenario, candidate)

    return {
        "tested_candidate_sha": candidate,
        "repository_head_sha": head,
        "source_digest_sha256": provenance[0]["day31_source_sha256"],
        "upstream": {
            p: {
                "run_id": v["id"],
                "attempt": v["run_attempt"],
                "head_sha": v["head_sha"],
                "event": v["event"],
            }
            for p, v in sorted(runs.items())
        },
        "day35_local_acceptance": d35["decision"],
        "day37_aws_mode": "AUDIT_ONLY",
    }


def evaluate(
    api: GitHub, event_name: str, event: dict[str, Any], env: dict[str, str]
) -> dict[str, Any]:
    require(env.get("GITHUB_REPOSITORY") == REPO, "wrong GitHub repository")
    if event_name == "workflow_run":
        trigger = event.get("workflow_run", {})
        require(
            event.get("repository", {}).get("full_name") == REPO
            and trigger.get("repository", {}).get("full_name") == REPO,
            "foreign workflow_run repository",
        )
        head, orig_event, branch = (
            trigger.get("head_sha"),
            trigger.get("event"),
            trigger.get("head_branch"),
        )
        require(
            orig_event in {"pull_request", "push"}
            and trigger.get("status") == "completed"
            and trigger.get("path", "").split("@", 1)[0] in set(WORKFLOWS) | {DAY38_PATH},
            "untrusted workflow_run event/trigger",
        )
        trigger_path = trigger["path"].split("@", 1)[0]
    elif event_name == "workflow_dispatch":
        inputs = event.get("inputs") or {}
        require(
            isinstance(inputs, dict) and inputs.get("mode") == "recheck",
            "manual dispatch must request read-only recheck mode",
        )
        require(
            env.get("GITHUB_REF") == "refs/heads/main"
            and event.get("repository", {}).get("full_name") == REPO,
            "manual readiness restricted to main",
        )
        head, orig_event, branch, trigger_path = env.get("GITHUB_SHA"), "push", "main", None
        require(api.get("commits/main").get("sha") == head, "dispatched source is stale")
    elif event_name == "schedule":
        require(
            env.get("GITHUB_REF") == "refs/heads/main" and event.get("schedule") == "17 * * * *",
            "scheduled readiness restricted to reviewed default-branch cron",
        )
        repository = event.get("repository")
        require(
            repository is None
            or (isinstance(repository, dict) and repository.get("full_name") == REPO),
            "foreign scheduled readiness repository",
        )
        head, orig_event, branch, trigger_path = env.get("GITHUB_SHA"), "push", "main", None
        require(api.get("commits/main").get("sha") == head, "scheduled source is stale")
    else:
        raise ValueError("unsupported trusted evaluator event")
    require(
        isinstance(head, str)
        and SHA.fullmatch(head) is not None
        and isinstance(branch, str)
        and len(branch) <= 200,
        "malformed head/branch",
    )
    require(orig_event != "push" or branch == "main", "non-main push is not eligible")
    verify_main_ruleset(api.get(f"rulesets/{MAIN_RULESET_ID}"))
    all_runs = api.runs(head)
    runs = selected_runs(all_runs, head, orig_event, branch)
    if trigger_path is not None and trigger_path != DAY38_PATH:
        latest = runs.get(trigger_path)
        require(
            latest is not None
            and latest["id"] == trigger["id"]
            and latest["run_attempt"] == trigger["run_attempt"],
            "superseded/stale workflow_run trigger",
        )
    proof = verify_existing(api, runs, head, orig_event, branch)
    offline = verify_day38_offline(
        api, all_runs, head, orig_event, branch, proof["tested_candidate_sha"]
    )
    if event_name == "workflow_dispatch":
        inputs = event.get("inputs") or {}
        bound = (
            inputs.get("source_commit"),
            inputs.get("source_run_id"),
            inputs.get("source_attempt"),
        )
        # Human read-only dispatch may omit all source arguments, but a partial
        # or stale self-dispatch is never allowed to claim a new offline run.
        require(all(bound) or not any(bound), "partial post-offline dispatch identity")
        if all(bound):
            require(
                bound == (head, str(offline["run_id"]), str(offline["run_attempt"])),
                "post-offline dispatch source/run/attempt mismatch",
            )
    if trigger_path == DAY38_PATH:
        # This separately chained observer handles the case where all seven
        # upstream checks completed BEFORE the slower Day38 offline run.
        require(
            trigger.get("conclusion") == "success"
            and offline["run_id"] == trigger.get("id")
            and offline["run_attempt"] == trigger.get("run_attempt"),
            "superseded or failed Day38 offline completion trigger",
        )
    return {
        "schema_version": "day38.v1",
        "decision": "READY_FOR_STAGING_REVIEW",
        "event": orig_event,
        "head_branch": branch,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "production_authorized": False,
        "release_authorized": False,
        "aws_plan_or_apply_executed": False,
        "physical_ecu_verified": False,
        "day38_offline": offline,
        **proof,
    }


def await_offline_completion(
    api: GitHub,
    event: dict[str, Any],
    env: dict[str, str],
    *,
    max_checks: int = 36,
    interval: float = 5.0,
) -> dict[str, Any]:
    """Wait for the same-workflow push to COMPLETELY finish before rechecking.

    The push dispatcher executes inside its origin run: GitHub may start the
    new workflow_dispatch before marking the original run `completed`.
    This bounded wait prevents a false BLOCKED result while preserving strict
    SHA, attempt, event, path and current-main checks. Never grants authority.
    """
    require(
        env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("GITHUB_REPOSITORY") == REPO,
        "offline completion wait restricted to trusted-main dispatch",
    )
    require(event.get("repository", {}).get("full_name") == REPO, "untrusted dispatch repository")
    inputs = event.get("inputs") or {}
    require(
        isinstance(inputs, dict) and inputs.get("mode") == "recheck",
        "origin wait requires recheck mode",
    )
    sha = inputs.get("source_commit")
    run_id = inputs.get("source_run_id")
    attempt = inputs.get("source_attempt")
    require(
        isinstance(sha, str)
        and SHA.fullmatch(sha) is not None
        and sha == env.get("GITHUB_SHA")
        and isinstance(run_id, str)
        and re.fullmatch(r"[1-9][0-9]*", run_id)
        and isinstance(attempt, str)
        and re.fullmatch(r"[1-9][0-9]*", attempt),
        "invalid self-dispatched source SHA/run/attempt",
    )
    require(1 <= max_checks <= 50 and 0 <= interval <= 10, "unsafe offline wait bounds")
    for check in range(max_checks):
        run = api.get(f"actions/runs/{run_id}")
        require(
            run.get("id") == int(run_id)
            and run.get("run_attempt") == int(attempt)
            and run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and str(run.get("path", "")).split("@", 1)[0] == DAY38_PATH
            and run.get("name") == DAY38_NAME,
            "origin offline workflow identity changed",
        )
        state = run.get("status")
        if state == "completed":
            require(
                run.get("conclusion") == "success",
                "original offline workflow did not complete successfully",
            )
            require(
                api.get("commits/main").get("sha") == sha,
                "protected main advanced during offline completion wait",
            )
            return {
                "schema_version": "day38.origin.v1",
                "decision": "OFFLINE_ORIGIN_COMPLETED",
                "source_commit": sha,
                "source_run_id": int(run_id),
                "source_attempt": int(attempt),
                "release_authorized": False,
                "aws_plan_or_apply_executed": False,
            }
        require(
            state in {"queued", "in_progress", "waiting", "pending", "requested"},
            "unknown upstream workflow state",
        )
        if check + 1 < max_checks:
            time.sleep(interval)
    raise ValueError("original Day38 offline workflow did not complete within bounded poll")


def write(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    if name := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(name).open("a", encoding="utf-8") as out:
            out.write(
                f"## Day38 release readiness\n\nDecision: **{result['decision']}**\n\n"
                "AWS deployment authority: **false**.\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["audit", "evaluate", "await-offline"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "audit":
        results = {
            k: os.environ.get(f"DAY38_{k.upper()}", "missing")
            for k in ("baseline", "terraform", "security", "regression")
        }
        success = all(v == "success" for v in results.values())
        write(
            args.output,
            {
                "schema_version": "day38.v1",
                "decision": "OFFLINE_AUDIT_PASS" if success else "BLOCKED",
                "checks": results,
                "commit": os.environ.get("GITHUB_SHA"),
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "release_authorized": False,
                "real_aws_verified": False,
            },
        )
        return 0 if success else 1

    if args.operation == "await-offline":
        try:
            event = strict_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
            result = await_offline_completion(
                GitHub(os.environ.get("GH_TOKEN", "")), event, dict(os.environ)
            )
        except (ValueError, KeyError, OSError, TypeError, urllib.error.URLError) as exc:
            # Never let a failed source wait become a successful readiness result.
            print("Day38 bounded origin wait: BLOCKED (" + type(exc).__name__ + ")")
            return 1
        write(args.output, result)
        return 0

    try:
        event = strict_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
        result = evaluate(
            GitHub(os.environ.get("GH_TOKEN", "")),
            os.environ.get("GITHUB_EVENT_NAME", ""),
            event,
            dict(os.environ),
        )
    except (
        ValueError,
        KeyError,
        OSError,
        TypeError,
        zipfile.BadZipFile,
        urllib.error.URLError,
    ) as exc:
        # URLs and redirected object-store errors could contain signed tokens.
        # Never persist or print arbitrary network/OS exceptions.
        reason = (
            "GitHub evidence network or local I/O verification failed"
            if isinstance(exc, (urllib.error.URLError, OSError))
            else str(exc).replace("\n", " ")[:350]
        )
        result = {
            "schema_version": "day38.v1",
            "decision": "BLOCKED",
            "reason_code": type(exc).__name__,
            "reason": reason,
            "release_authorized": False,
            "production_authorized": False,
            "aws_plan_or_apply_executed": False,
            "generated_at_utc": datetime.now(UTC).isoformat(),
        }
    write(args.output, result)
    print("Day38 decision: " + result["decision"])
    return 0 if result["decision"] == "READY_FOR_STAGING_REVIEW" else 1


if __name__ == "__main__":
    sys.exit(main())
