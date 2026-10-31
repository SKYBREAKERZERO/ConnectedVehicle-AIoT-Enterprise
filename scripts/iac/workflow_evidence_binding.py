"""Read-only GitHub CI identity binding. Artifacts are data, never executable code."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from scripts.iac.ci_baseline_policy import REPOSITORY, sha
from scripts.iac.plan_admission import canonical_digest, ruleset_errors

WORKFLOWS = {
    ".github/workflows/ci.yml": ("IaC quality gate", "day31-iac-trust"),
    ".github/workflows/runtime.yml": ("Runtime quality gate", "day31-runtime-trust"),
}
SOURCE_FILES = [
    "scripts/iac/module_contracts.py",
    "tests/unit/iac/test_module_contracts.py",
    "tests/integration/remote_command/conftest.py",
    "tests/integration/remote_command/test_remote_command_sqs_worker_integration.py",
    "scripts/iac/pipeline_fault_probe.py",
    "scripts/verify_ci_database_identity.py",
    "tests/unit/iac/test_pipeline_fault_probe.py",
    "tests/unit/test_management_credentials.py",
    "pyproject.toml",
    ".github/workflows/ci-fault-matrix.yml",
    ".github/workflows/ci-fault-case.yml",
    "scripts/iac/pipeline_evidence.py",
    "tests/unit/iac/test_pipeline_evidence.py",
    "tests/unit/iac/test_workflow.py",
    ".github/workflows/runtime-core.yml",
    ".github/workflows/runtime-postgres.yml",
    ".github/workflows/iac-phase.yml",
    ".github/actions/setup-ci-runtime/action.yml",
    ".github/actions/setup-ci-iac/action.yml",
    "scripts/iac/ci_baseline_policy.py",
    "scripts/iac/gate.py",
    "scripts/iac/trusted_state_registry.py",
    "scripts/iac/plan_admission.py",
    "scripts/iac/workflow_evidence_binding.py",
    "scripts/iac/day31_evidence.py",
    "scripts/iac/release_admission.py",
    "scripts/iac/release_revalidation.py",
    "scripts/iac/recovery_approval.py",
    "scripts/iac/failure_isolation.py",
    "tests/unit/iac/test_ci_baseline_policy.py",
    "tests/unit/iac/test_workflow_evidence_binding.py",
    "tests/unit/iac/test_day31_evidence.py",
    "tests/integration/iac/test_day31_admission_races.py",
    "tests/integration/iac/test_day31_workflow_provenance.py",
    ".github/workflows/ci.yml",
    ".github/workflows/runtime.yml",
    ".github/workflows/day31-trust-boundary.yml",
]


def digest_sources(files: dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for name in sorted(SOURCE_FILES):
        h.update(name.encode() + b"\0")
        h.update(files[name])
    return h.hexdigest()


def timestamp(value: str) -> datetime:
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("UTC timestamp required")
    return t


def latest(runs: list[dict[str, Any]], path: str, context: dict[str, Any]) -> dict[str, Any]:
    matches = [
        r
        for r in runs
        if r["path"] == path
        and r["head_sha"] == context["head_sha"]
        and r["event"] == context["event"]
    ]
    if not matches:
        raise ValueError("no matching workflow run")
    if any(type(r.get("run_attempt")) is not int or r["run_attempt"] < 1 for r in matches):
        raise ValueError("invalid workflow attempt identity")
    run = max(matches, key=lambda r: (timestamp(r["created_at"]), r["id"], r["run_attempt"]))
    if (
        run["status"] != "completed"
        or run["conclusion"] != "success"
        or run["repository"]["full_name"] != REPOSITORY
        or run["head_repository"]["full_name"] != context["head_repository"]
        or type(run["run_attempt"]) is not int
        or run["run_attempt"] < 1
    ):
        raise ValueError("latest run is not eligible; never fall back to historical green")
    return run


def unpack(raw: bytes, metadata: dict[str, Any], run: dict[str, Any]) -> dict[str, bytes]:
    if (
        metadata["expired"] is not False
        or metadata["workflow_run"]["id"] != run["id"]
        or metadata["digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
        or len(raw) > 30_000_000
        or timestamp(metadata["created_at"]) < timestamp(run["run_started_at"])
    ):
        raise ValueError("artifact digest/owner/time mismatch")
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        if sum(i.file_size for i in z.infolist()) > 30_000_000 or len(z.infolist()) > 12:
            raise ValueError("oversized artifact")
        for item in z.infolist():
            if item.is_dir():
                continue
            if (
                re.fullmatch("[a-z0-9_-]+[.](json|xml)", item.filename) is None
                or item.filename in result
                or (item.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("unsafe/duplicate artifact member")
            result[item.filename] = z.read(item)
    return result


def bind(
    context: dict[str, Any],
    runs: dict[str, list[dict[str, Any]]],
    jobs: dict[int, list[dict[str, Any]]],
    artifacts: dict[int, tuple[dict[str, Any], bytes]],
    files: dict[str, bytes],
) -> dict[str, Any]:
    candidate = sha(context["candidate_sha"])
    head = sha(context["head_sha"])
    baseline = sha(context["baseline_sha"])
    if baseline == candidate:
        raise ValueError("self baseline")
    if context["event"] == "pull_request":
        if context["parents"] != [baseline, head] or context["current_merge_sha"] != candidate:
            raise ValueError("PR current merge identity mismatch")
    elif context["event"] not in {"push", "merge_group", "workflow_dispatch"}:
        raise ValueError("unsupported aggregation event")
    receipts = {}
    for path, (job_name, artifact_name) in WORKFLOWS.items():
        run = latest(runs[path], path, context)
        required = [j for j in jobs[run["id"]] if j["name"] == job_name]
        if (
            len(required) != 1
            or required[0]["status"] != "completed"
            or required[0]["conclusion"] != "success"
        ):
            raise ValueError("required job failed/skipped/missing")
        meta, raw = artifacts[run["id"]]
        if meta["name"] != artifact_name:
            raise ValueError("unexpected artifact")
        data = unpack(raw, meta, run)
        name = "day31-baseline.json" if path.endswith("/ci.yml") else "day31-runtime-baseline.json"
        record = json.loads(data[name])
        expected = {
            "candidate_sha": candidate,
            "baseline_sha": baseline,
            "event": context["event"],
            "repository": REPOSITORY,
            "pr_number": context.get("pr_number"),
            "pr_head_sha": head if context["event"] == "pull_request" else None,
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            "selector_sha256": hashlib.sha256(
                files["scripts/iac/ci_baseline_policy.py"]
            ).hexdigest(),
        }
        if any(
            type(record.get(k)) is not type(v) or record.get(k) != v for k, v in expected.items()
        ):
            raise ValueError("baseline candidate/run/attempt/source binding mismatch")
        proof_name = "day31-governance.json" if path.endswith("/ci.yml") else "day31-runtime.json"
        proof = json.loads(data[proof_name])
        prefix = "day31" if path.endswith("/ci.yml") else "day31_runtime"
        p = proof["provenance"]
        if (
            p[prefix + "_commit"] != candidate
            or p[prefix + "_run_id"] != f"{run['id']}:{run['run_attempt']}"
            or p[prefix + "_source_sha256"] != digest_sources(files)
            or proof["baseline_sha256"] != hashlib.sha256(data[name]).hexdigest()
            or proof["apply_authorized"] is not False
        ):
            raise ValueError("evidence source/attempt/hash mismatch")
        if path.endswith("/ci.yml"):
            from scripts.iac.day31_evidence import verify_documents

            verify_documents(
                data["day25-security.xml"],
                data["day31-faults.xml"],
                data["day31-faults.json"],
                proof["provenance"],
            )
            if (
                proof["unit_junit_sha256"] != hashlib.sha256(data["day25-security.xml"]).hexdigest()
                or proof["fault_junit_sha256"]
                != hashlib.sha256(data["day31-faults.xml"]).hexdigest()
                or proof["fault_report_sha256"]
                != hashlib.sha256(data["day31-faults.json"]).hexdigest()
            ):
                raise ValueError("JUnit/report hash mismatch")
        receipts[path] = {
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            "required_job_id": required[0]["id"],
            "artifact_id": meta["id"],
            "artifact_digest": meta["digest"],
            "evidence_sha256": hashlib.sha256(data[proof_name]).hexdigest(),
            "candidate_sha": candidate,
        }
    return {
        "scope": "read-only-ci-identity-binding",
        "candidate": context,
        "workflows": receipts,
        "apply_authorized": False,
        "release_authorized": False,
    }


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        url = urllib.parse.urlparse(newurl)
        if (
            url.scheme != "https"
            or not url.hostname
            or not (
                url.hostname == "api.github.com"
                or url.hostname.endswith(
                    (
                        ".blob.core.windows.net",
                        ".actions.githubusercontent.com",
                        ".githubusercontent.com",
                    )
                )
            )
        ):
            raise ValueError("unexpected artifact redirect host")
        # Bearer credentials never cross the GitHub API origin.
        return urllib.request.Request(newurl, headers={"User-Agent": "day31-readonly-verifier"})


class GitHub:
    def __init__(self) -> None:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ValueError("read-only GitHub token required")
        self.token = str(token)

    def raw(self, path: str, limit: int = 30_000_000) -> bytes:
        req = urllib.request.Request(
            "https://api.github.com/repos/" + REPOSITORY + "/" + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "User-Agent": "day31-readonly-verifier",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.build_opener(Redirect()).open(req, timeout=45) as response:
                raw = response.read(limit + 1)
        except Exception:
            raise ValueError("GitHub read failed; no fallback or signed URL disclosure") from None
        if len(raw) > limit:
            raise ValueError("GitHub response exceeds bound")
        return bytes(raw)

    def get(self, path: str) -> Any:
        return json.loads(self.raw(path))

    def pages(self, path: str, key: str) -> list[dict[str, Any]]:
        result = []
        for page in range(1, 11):
            data = self.get(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
            rows = data[key]
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise ValueError("bounded API pagination exhausted; fail closed")

    def file(self, name: str, commit: str) -> bytes:
        data = self.get("contents/" + name + "?ref=" + sha(commit))
        if data["encoding"] != "base64":
            raise ValueError("unexpected blob encoding")
        return base64.b64decode(data["content"], validate=False)


def live(api: GitHub, pr_number: int) -> dict[str, Any]:
    rules = api.get("rulesets/24828733")
    if ruleset_errors(rules):
        raise ValueError("main ruleset no longer enforces independent review and both gates")
    pr = api.get(f"pulls/{pr_number}")
    if pr["state"] != "open" or pr["base"]["ref"] != "main":
        raise ValueError("current open main PR required")
    candidate = sha(pr["merge_commit_sha"])
    parents = [p["sha"] for p in api.get("git/commits/" + candidate)["parents"]]
    context = {
        "event": "pull_request",
        "pr_number": pr_number,
        "candidate_sha": candidate,
        "current_merge_sha": candidate,
        "parents": parents,
        "baseline_sha": parents[0],
        "head_sha": sha(pr["head"]["sha"]),
        "head_repository": pr["head"]["repo"]["full_name"],
    }
    runs = {}
    jobs = {}
    artifacts = {}
    for path, (_, name) in WORKFLOWS.items():
        workflow = path.rsplit("/", 1)[-1]
        runs[path] = api.pages(
            f"actions/workflows/{workflow}/runs?head_sha=" + context["head_sha"], "workflow_runs"
        )
        run = latest(runs[path], path, context)
        attempt = api.get(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}")
        if attempt["head_sha"] != run["head_sha"] or attempt["run_attempt"] != run["run_attempt"]:
            raise ValueError("attempt identity mismatch")
        run["run_started_at"] = attempt["run_started_at"]
        jobs[run["id"]] = api.pages(
            f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs"
        )
        matches = [
            a
            for a in api.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
            if a["name"] == name and timestamp(a["created_at"]) >= timestamp(run["run_started_at"])
        ]
        if len(matches) != 1:
            raise ValueError("missing/duplicate current-attempt artifact")
        meta = matches[0]
        artifacts[run["id"]] = (meta, api.raw(f"actions/artifacts/{meta['id']}/zip"))
    files = {name: api.file(name, candidate) for name in SOURCE_FILES}
    report = bind(context, runs, jobs, artifacts, files)
    # Re-read live identities after downloads. A newer cancelled/pending run or
    # changed PR invalidates this snapshot rather than reusing old green evidence.
    current_pr = api.get(f"pulls/{pr_number}")
    if (
        current_pr["merge_commit_sha"] != candidate
        or current_pr["head"]["sha"] != context["head_sha"]
    ):
        raise ValueError("candidate changed during inspection")
    for path, receipt in report["workflows"].items():
        newer = latest(
            api.pages(
                f"actions/workflows/{path.rsplit('/', 1)[-1]}/runs?head_sha=" + context["head_sha"],
                "workflow_runs",
            ),
            path,
            context,
        )
        if (newer["id"], newer["run_attempt"]) != (receipt["run_id"], receipt["run_attempt"]):
            raise ValueError("workflow changed during inspection")
    main = api.get("git/ref/heads/main")["object"]["sha"]
    installed = False
    with suppress(ValueError):
        installed = (
            api.file("scripts/iac/workflow_evidence_binding.py", main)
            == files["scripts/iac/workflow_evidence_binding.py"]
            and api.file(".github/workflows/day31-trust-boundary.yml", main)
            == files[".github/workflows/day31-trust-boundary.yml"]
        )
    if canonical_digest(api.get("rulesets/24828733")) != canonical_digest(rules):
        raise ValueError("main governance changed during inspection")
    report.update(
        trusted_control_plane_installed=installed,
        trusted_main_sha=main,
        main_ruleset_sha256=canonical_digest(rules),
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    entry = parser.add_mutually_exclusive_group(required=True)
    entry.add_argument("--pr", type=int)
    entry.add_argument("--trigger-run", type=int)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--inspect-uninstalled",
        action="store_true",
        help="Local read-only audit only; cannot qualify trusted-main execution",
    )
    args = parser.parse_args()
    api = GitHub()
    pr = args.pr
    if args.trigger_run:
        run = api.get(f"actions/runs/{args.trigger_run}")
        if run["event"] != "pull_request":
            raise ValueError("only PR completion aggregation supported")
        candidates = [
            p
            for p in api.get("commits/" + sha(run["head_sha"]) + "/pulls")
            if p["state"] == "open"
            and p["base"]["ref"] == "main"
            and p["head"]["sha"] == run["head_sha"]
        ]
        if len(candidates) != 1:
            raise ValueError("ambiguous/stale PR association")
        pr = candidates[0]["number"]
    if pr is None or pr <= 0:
        raise ValueError("positive PR number required")
    report = live(api, pr)
    on_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if on_actions and (
        os.environ.get("GITHUB_EVENT_NAME") not in {"workflow_run", "workflow_dispatch"}
        or os.environ.get("GITHUB_WORKFLOW_REF")
        != REPOSITORY + "/.github/workflows/day31-trust-boundary.yml@refs/heads/main"
    ):
        raise ValueError("trusted aggregation requires protected-main workflow context")
    if not report["trusted_control_plane_installed"] and (
        not args.inspect_uninstalled or on_actions
    ):
        raise ValueError("trusted-main control plane not installed; no qualified binding")
    report["verification_mode"] = (
        "trusted-main-api-check" if on_actions else "local-readonly-api-inspection"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("CI identity binding verified; no release or Apply authority")


if __name__ == "__main__":
    main()
