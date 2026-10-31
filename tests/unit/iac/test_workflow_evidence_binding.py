"""F05/F06/F12: API identity and artifact binding, never artifact-presence trust."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from copy import deepcopy
from typing import Any

import pytest

from scripts.iac.ci_baseline_policy import REPOSITORY
from scripts.iac.workflow_evidence_binding import (
    SOURCE_FILES,
    WORKFLOWS,
    bind,
    digest_sources,
)
from tests.unit.iac.test_ci_baseline_policy import A, B, C


def documents() -> tuple[bytes, bytes, bytes, dict[str, str]]:
    from xml.etree import ElementTree as ET

    from scripts.iac.day31_evidence import FAULT_CASES, UNIT_CASES

    p = {
        "day31_commit": C,
        "day31_run_id": "10:1",
        "day31_source_sha256": digest_sources({n: b"source" for n in SOURCE_FILES}),
    }

    def xml(names: list[str]) -> bytes:
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite")
        props = ET.SubElement(suite, "properties")
        for k, v in p.items():
            ET.SubElement(props, "property", name=k, value=v)
        for name in names:
            ET.SubElement(suite, "testcase", name=name)
        return ET.tostring(root)

    facts = {
        "provenance": p,
        "isolation": {
            "crash": {
                "quarantines": 1,
                "audit_matches": 1,
                "audit_failure_rollback_counts": [0, 0],
                "original_rows_preserved": True,
            },
            "reconciled": {"original_rows_preserved": True, "reconciled_still_denied": True},
        },
        "unknown": {"consumptions": 1, "consumption_audits": 1, "commit_lookup_matches": True},
        "race": {"quarantines": 1, "audits": 1, "unique_operations": 1, "exit_codes": [0, 0]},
        "lock_consumptions": 1,
        "revocation": [
            {
                "order": o,
                "admission_exit": 0 if o == "admission-first" else 23,
                "revoke_exit": 0,
                "ready_count": 0,
                "consumptions": 1,
                "post_revoke_denied": True,
            }
            for o in ("admission-first", "revoke-first")
        ],
    }
    return xml(sorted(UNIT_CASES)), xml(sorted(FAULT_CASES)), json.dumps(facts).encode(), p


def sample() -> tuple[Any, ...]:
    context = {
        "event": "pull_request",
        "candidate_sha": C,
        "baseline_sha": A,
        "head_sha": B,
        "head_repository": REPOSITORY,
        "pr_number": 15,
        "parents": [A, B],
        "current_merge_sha": C,
    }
    files = {n: b"source" for n in SOURCE_FILES}
    runs = {}
    jobs = {}
    artifacts = {}
    for index, (path, (job, name)) in enumerate(WORKFLOWS.items(), 10):
        run = {
            "id": index,
            "path": path,
            "head_sha": B,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            "created_at": "2026-10-31T00:00:00Z",
            "run_started_at": "2026-10-31T00:00:00Z",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
        }
        runs[path] = [run]
        jobs[index] = [
            {"id": index * 10, "name": job, "status": "completed", "conclusion": "success"}
        ]
        baseline = {
            "repository": REPOSITORY,
            "event": "pull_request",
            "candidate_sha": C,
            "baseline_sha": A,
            "pr_number": 15,
            "pr_head_sha": B,
            "run_id": index,
            "run_attempt": 1,
            "selector_sha256": hashlib.sha256(
                files["scripts/iac/ci_baseline_policy.py"]
            ).hexdigest(),
        }
        rawbase = json.dumps(baseline).encode()
        base_name = "day31-baseline.json" if index == 10 else "day31-runtime-baseline.json"
        prefix = "day31" if index == 10 else "day31_runtime"
        proof = {
            "provenance": {
                prefix + "_commit": C,
                prefix + "_run_id": f"{index}:1",
                prefix + "_source_sha256": digest_sources(files),
            },
            "baseline_sha256": hashlib.sha256(rawbase).hexdigest(),
            "apply_authorized": False,
        }
        members = {base_name: rawbase}
        if index == 10:
            unit, fault, facts, _ = documents()
            members.update(
                {"day25-security.xml": unit, "day31-faults.xml": fault, "day31-faults.json": facts}
            )
            proof.update(
                unit_junit_sha256=hashlib.sha256(unit).hexdigest(),
                fault_junit_sha256=hashlib.sha256(fault).hexdigest(),
                fault_report_sha256=hashlib.sha256(facts).hexdigest(),
            )
        members["day31-governance.json" if index == 10 else "day31-runtime.json"] = json.dumps(
            proof
        ).encode()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for n, v in members.items():
                z.writestr(n, v)
        raw = buf.getvalue()
        artifacts[index] = (
            {
                "id": index * 100,
                "name": name,
                "expired": False,
                "workflow_run": {"id": index},
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "created_at": "2026-10-31T00:01:00Z",
            },
            raw,
        )
    return context, runs, jobs, artifacts, files


def test_matching_api_runs_and_hashed_evidence_bind_without_release_authority() -> None:
    r = bind(*sample())
    assert len(r["workflows"]) == 2 and r["release_authorized"] is False


@pytest.mark.parametrize(
    "flow",
    [
        "F05",
        "F06",
        "F12",
        "job-skipped",
        "artifact-tampered",
        "expired",
        "newer-pending",
        "merge-changed",
    ],
)
def test_workflow_identity_attack_flows_are_denied(flow: str) -> None:
    context, runs, jobs, artifacts, files = deepcopy(sample())
    runtime = runs[".github/workflows/runtime.yml"][0]
    if flow == "F05":
        runtime["head_sha"] = A
    if flow == "F06":
        runs[".github/workflows/runtime.yml"].append(
            {**runtime, "id": 100, "created_at": "2026-10-31T01:00:00Z", "conclusion": "cancelled"}
        )
    if flow == "F12":
        runtime["run_attempt"] = 2
    if flow == "job-skipped":
        jobs[11][0]["conclusion"] = "skipped"
    if flow == "artifact-tampered":
        artifacts[10] = (artifacts[10][0], artifacts[10][1] + b"tampered")
    if flow == "expired":
        artifacts[10][0]["expired"] = True
    if flow == "newer-pending":
        runs[".github/workflows/runtime.yml"].append(
            {
                **runtime,
                "id": 100,
                "created_at": "2026-10-31T01:00:00Z",
                "status": "in_progress",
                "conclusion": None,
            }
        )
    if flow == "merge-changed":
        context["current_merge_sha"] = B
    with pytest.raises(ValueError):
        bind(context, runs, jobs, artifacts, files)
