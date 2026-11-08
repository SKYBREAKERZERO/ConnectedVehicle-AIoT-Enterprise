"""Offline negative acceptance for Day38 source and artifact trust boundary."""

import hashlib
import io
import json
import zipfile
from typing import Any, cast

import pytest

from scripts.day38_readiness import (
    REPO,
    check_zip,
    digest,
    json_artifact,
    locate_artifact,
    selected_runs,
    strict_json,
    validate_baseline,
    verify_main_ruleset,
    verify_sealed,
)

SHA = "a" * 40
MERGE = "b" * 40
SOURCE = "c" * 64


def make_run(
    path: str,
    *,
    status: str = "completed",
    conclusion: str = "success",
    run_id: int = 11,
    start: str = "2026-11-07T10:00:00Z",
) -> dict[str, Any]:
    from scripts.day38_readiness import WORKFLOWS

    return {
        "path": path,
        "name": WORKFLOWS[path],
        "head_sha": SHA,
        "head_branch": "feat/day38",
        "event": "pull_request",
        "status": status,
        "conclusion": conclusion,
        "id": run_id,
        "run_attempt": 1,
        "run_started_at": start,
    }


def zipped(members: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for k, v in members.items():
            archive.writestr(k, v)
    return out.getvalue()


def manifest(run_id: int = 11, candidate: str = MERGE) -> dict[str, Any]:
    return {
        "version": 1,
        "stage": "iac-evidence",
        "provenance": {
            "day31_commit": candidate,
            "day31_run_id": f"{run_id}:1",
            "day31_source_sha256": SOURCE,
        },
        "files": {"report.json": digest(b"{}")},
    }


def test_json_duplicate_key_denied() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        strict_json(b'{"decision":"PASS","decision":"BLOCKED"}')


def test_nonfinite_denied() -> None:
    with pytest.raises(ValueError, match="nonfinite"):
        strict_json(b'{"value":NaN}')


def test_zip_traversal_denied() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        check_zip(zipped({"../payload.json": b"{}"}))


def test_zip_member_collision_denied() -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("report.json", b"{}")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("report.json", b"{}")
    with pytest.raises(ValueError, match="duplicate"):
        check_zip(out.getvalue())


def test_seal_validates_candidate_and_attempt() -> None:
    content = {"report.json": b"{}", "manifest.json": json.dumps(manifest()).encode()}
    run = {"id": 11, "run_attempt": 1}
    proof, members = verify_sealed(content, "iac-evidence", run)
    assert proof["day31_commit"] == MERGE
    assert members["report.json"] == b"{}"
    with pytest.raises(ValueError, match="attempt"):
        verify_sealed(content, "iac-evidence", {"id": 11, "run_attempt": 2})
    content["report.json"] = b'{"tampered":true}'
    with pytest.raises(ValueError, match="hash"):
        verify_sealed(content, "iac-evidence", run)


def test_new_failure_overrides_old_green() -> None:
    from scripts.day38_readiness import WORKFLOWS

    rows = [make_run(path) for path in WORKFLOWS]
    bad = make_run(
        ".github/workflows/ci.yml", conclusion="failure", run_id=99, start="2026-11-07T11:00:00Z"
    )
    rows.append(bad)
    with pytest.raises(ValueError, match="not successful"):
        selected_runs(rows, SHA, "pull_request", "feat/day38")


def test_missing_workflow_fails_closed() -> None:
    with pytest.raises(ValueError, match="missing required workflow"):
        selected_runs([make_run(".github/workflows/ci.yml")], SHA, "pull_request", "feat/day38")


def test_baseline_merge_and_pr_head_must_both_match() -> None:
    run = {"id": 11, "run_attempt": 1, "head_branch": "feat/day38"}
    b = {
        "repository": REPO,
        "event": "pull_request",
        "run_id": 11,
        "run_attempt": 1,
        "candidate_sha": MERGE,
        "pr_head_sha": SHA,
        "ref": "refs/pull/16/merge",
        "pr_number": 16,
    }
    assert validate_baseline(b, run, SHA, "pull_request", "feat/day38") == MERGE
    with pytest.raises(ValueError, match="PR head"):
        validate_baseline({**b, "pr_head_sha": "d" * 40}, run, SHA, "pull_request", "feat/day38")


def test_expired_artifact_denied() -> None:
    a = {
        "name": "proof",
        "id": 15,
        "expired": True,
        "size_in_bytes": 123,
        "digest": "sha256:" + hashlib.sha256(b"zip").hexdigest(),
    }
    with pytest.raises(ValueError, match="expired"):
        locate_artifact([a], "proof", {"id": 11, "head_sha": SHA})


def test_artifact_duplicate_denied() -> None:
    a = {
        "name": "proof",
        "id": 15,
        "expired": False,
        "size_in_bytes": 123,
        "digest": "sha256:" + digest(b"zip"),
    }
    with pytest.raises(ValueError, match="duplicate"):
        locate_artifact([a, dict(a)], "proof", {"id": 11, "head_sha": SHA})


def test_unexpected_member_denied() -> None:
    with pytest.raises(ValueError, match="unexpected"):
        json_artifact({"result.json": b"{}", "extra.json": b"{}"}, "result.json")


def fault_receipt(graph: str, scenario: str, run: dict[str, Any]) -> dict[str, Any]:
    """Construct a report with the exact schema emitted by pipeline_fault_probe.py."""
    step = (
        "guard"
        if scenario in {"failure", "skipped"}
        else "download"
        if scenario == "missing-artifact"
        else "verify"
    )
    outputs = {"guard": "success", "download": "success", "verify": "success"}
    outputs[step] = "failure"
    return {
        "scope": "isolated-actions-scheduler-and-artifact-probe",
        "graph": graph,
        "scenario": scenario,
        "commit": MERGE,
        "run_id": str(run["id"]),
        "attempt": run["run_attempt"],
        "historical_input_attempt": (
            "1" if scenario == "old-attempt" and run["run_attempt"] > 1 else None
        ),
        "producer_attempt": (None if scenario == "skipped" else str(run["run_attempt"])),
        "single_fault_isolated": True,
        "fault_blocked": True,
        "deployment_authorized": False,
        "observed_needs": {
            "producer": {
                "result": "skipped" if scenario == "skipped" else "success",
                "outputs": {}
                if scenario == "skipped"
                else {
                    "operation": "failure" if scenario == "failure" else "success",
                    "attempt": str(run["run_attempt"]),
                },
            },
            "consumer": {"result": "success", "outputs": outputs},
        },
    }


@pytest.mark.parametrize("graph", ("iac", "runtime"))
@pytest.mark.parametrize(
    "scenario",
    (
        "failure",
        "skipped",
        "missing-artifact",
        "tamper",
        "old-attempt",
    ),
)
def test_all_ten_fault_oracles_validate_actual_denials(graph: str, scenario: str) -> None:
    from scripts.day38_readiness import verify_fault_receipt

    run = {"head_sha": SHA, "id": 71, "run_attempt": 1}
    verify_fault_receipt(fault_receipt(graph, scenario, run), run, graph, scenario, MERGE)
    run2 = {**run, "run_attempt": 2}
    verify_fault_receipt(fault_receipt(graph, scenario, run2), run2, graph, scenario, MERGE)


@pytest.mark.parametrize(
    "damage",
    (
        "wrong_commit",
        "wrong_attempt",
        "fake_denial",
        "wrong_operation",
        "wrong_boundary",
        "foreign_producer",
        "missing_needs",
        "fake_authority",
        "wrong_history",
        "incorrect_scope",
    ),
)
def test_fault_oracle_tampering_never_grants_readiness(damage: str) -> None:
    from scripts.day38_readiness import verify_fault_receipt

    run = {"head_sha": SHA, "id": 71, "run_attempt": 2}
    r = fault_receipt("iac", "old-attempt", run)
    if damage == "wrong_commit":
        r["commit"] = "e" * 40
    elif damage == "wrong_attempt":
        r["attempt"] = 1
    elif damage == "fake_denial":
        r["fault_blocked"] = False
    elif damage == "wrong_operation":
        r["observed_needs"]["producer"]["outputs"]["operation"] = "failure"
    elif damage == "wrong_boundary":
        r["observed_needs"]["consumer"]["outputs"]["verify"] = "success"
    elif damage == "foreign_producer":
        r["producer_attempt"] = "1"
    elif damage == "missing_needs":
        r.pop("observed_needs")
    elif damage == "fake_authority":
        r["deployment_authorized"] = True
    elif damage == "wrong_history":
        r["historical_input_attempt"] = None
    elif damage == "incorrect_scope":
        r["scope"] = "something-else"
    with pytest.raises(ValueError):
        verify_fault_receipt(r, run, "iac", "old-attempt", MERGE)


def test_ready_requires_verified_day38_offline_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import day38_readiness as d

    run = {
        "path": d.DAY38_PATH,
        "name": d.DAY38_NAME,
        "head_sha": SHA,
        "head_branch": "feat/day38",
        "event": "pull_request",
        "id": 91,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "run_started_at": "2026-11-07T10:00:00Z",
    }
    source = {"repository": REPO, "candidate_sha": MERGE, "run_id": 91, "run_attempt": 1}
    receipt = {
        "schema_version": "day38.v1",
        "decision": "OFFLINE_AUDIT_PASS",
        "checks": {k: "success" for k in ("baseline", "terraform", "security", "regression")},
        "commit": MERGE,
        "run_id": "91",
        "run_attempt": "1",
        "release_authorized": False,
        "real_aws_verified": False,
    }
    archive = zipped({"day38-audit.json": json.dumps(receipt).encode()})
    stage_evidence = {
        name: {"manifest_sha256": SOURCE, "report_sha256": SOURCE, "source": source}
        for name in d.DAY38_REQUIRED_STAGES
    }
    aggregate = {
        "schema_version": "day38.aggregate.v1",
        "decision": "OFFLINE_STAGE_EVIDENCE_VERIFIED",
        "source": source,
        "mandatory_stages": list(d.DAY38_REQUIRED_STAGES),
        "stages": stage_evidence,
        "release_authorized": False,
        "aws_plan_or_apply_executed": False,
    }
    aggregate_data = json.dumps(aggregate).encode()
    envelope = {
        "version": 1,
        "stage": d.DAY38_AGGREGATE_STAGE,
        "provenance": {
            "day31_commit": MERGE,
            "day31_run_id": "91:1",
            "day31_source_sha256": SOURCE,
        },
        "files": {"aggregate.json": digest(aggregate_data)},
    }
    aggregate_zip = zipped(
        {"aggregate.json": aggregate_data, "manifest.json": json.dumps(envelope).encode()}
    )
    final_decision = {
        "schema_version": "day38.gate.v1",
        "decision": "OFFLINE_AUDIT_PASS",
        "source": source,
        "aggregate_sha256": digest(aggregate_data),
        "release_authorized": False,
        "aws_authorized": False,
    }
    final_zip = zipped({"decision.json": json.dumps(final_decision).encode()})
    zip_payloads = {151: archive, 152: aggregate_zip, 153: final_zip}
    names = {151: "day38-offline-91-1", 152: "day38-aggregate-91-1", 153: "day38-final-91-1"}
    artifacts = [
        {
            "id": key,
            "name": names[key],
            "expired": False,
            "digest": "sha256:" + digest(data),
            "size_in_bytes": len(data),
            "workflow_run": {"id": 91, "head_sha": SHA},
        }
        for key, data in zip_payloads.items()
    ]

    class FakeAPI:
        token = "x"

        def jobs(self, _id: int) -> list[dict[str, Any]]:
            offline_steps = [
                "Bind event candidate and independent ancestor baseline",
                "Validate all Terraform formatting and each AWS-only root",
                "Run pinned offline IaC security gate (no waiver bypass)",
                "Regress trust, Checkov and Day38 fail-closed rules",
                "Emit audit receipt even for failures",
                "Upload untrusted read-only audit diagnostics",
            ]
            jobs: list[dict[str, Any]] = [
                {"name": name, "conclusion": "success"} for name in d.DAY38_REQUIRED_JOB_NAMES
            ]
            jobs += [
                {
                    "name": d.DAY38_OFFLINE_JOB,
                    "conclusion": "success",
                    "steps": [{"name": k, "conclusion": "success"} for k in offline_steps],
                },
                {"name": d.DAY38_GATE_JOB, "conclusion": "success"},
            ]
            return jobs

        def artifacts(self, _id: int) -> list[dict[str, Any]]:
            return artifacts

    monkeypatch.setattr(
        d, "download_artifact", lambda artifact_id, *_args: zip_payloads[artifact_id]
    )
    api = cast(d.GitHub, FakeAPI())
    result = d.verify_day38_offline(api, [run], SHA, "pull_request", "feat/day38", MERGE)
    assert result["decision"] == "OFFLINE_AUDIT_PASS"
    assert result["enterprise"]["stage_count"] == len(d.DAY38_REQUIRED_STAGES)
    assert result["audit_sha256"] == digest(json.dumps(receipt).encode())
    with pytest.raises(ValueError, match="missing"):
        d.verify_day38_offline(api, [], SHA, "pull_request", "feat/day38", MERGE)
    with pytest.raises(ValueError, match="content/source"):
        d.verify_day38_offline(api, [run], SHA, "pull_request", "feat/day38", SHA)
    with pytest.raises(ValueError, match="did not succeed"):
        d.verify_day38_offline(
            api, [{**run, "conclusion": "failure"}], SHA, "pull_request", "feat/day38", MERGE
        )

    zip_payloads[153] = zipped(
        {"decision.json": json.dumps({**final_decision, "aggregate_sha256": "0" * 64}).encode()}
    )
    with pytest.raises(ValueError, match="aggregate"):
        d.verify_day38_offline(api, [run], SHA, "pull_request", "feat/day38", MERGE)


def test_latest_day38_offline_failure_supersedes_prior_green(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import day38_readiness as d

    first = {
        "path": d.DAY38_PATH,
        "name": d.DAY38_NAME,
        "event": "pull_request",
        "head_sha": SHA,
        "head_branch": "feat/day38",
        "id": 101,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "run_started_at": "2026-11-07T10:00:00Z",
    }
    latest = {**first, "id": 102, "conclusion": "failure", "run_started_at": "2026-11-07T11:00:00Z"}
    with pytest.raises(ValueError, match="did not succeed"):
        d.verify_day38_offline(
            cast(d.GitHub, object()), [first, latest], SHA, "pull_request", "feat/day38", MERGE
        )


def test_day38_yaml_does_not_cancel_or_conflate_gates() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/day38-release-readiness.yml").read_text()
    assert "cancel-in-progress: false" in workflow
    assert "cancel-in-progress: true" not in workflow
    assert "github.event_name }}-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "name: Day38 offline audit gate (not AWS release)" in workflow
    assert "name: Day38 upstream readiness gate (not PR-required)" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "id-token: write" not in workflow


def test_complete_readiness_verified_by_independent_mocked_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive flow covers 7 independent workflows, 4 reports, identity, hashes."""
    from scripts import day38_readiness as d

    rows = [make_run(path, run_id=101 + i) for i, path in enumerate(d.WORKFLOWS)]
    by_path = {r["path"]: r for r in rows}
    zip_data: dict[int, bytes] = {}
    artifact_data: dict[int, list[dict[str, Any]]] = {}
    next_id = 400

    def add(path: str, name: str, files: dict[str, bytes]) -> None:
        nonlocal next_id
        run = by_path[path]
        payload = zipped(files)
        zip_data[next_id] = payload
        artifact_data.setdefault(run["id"], []).append(
            {
                "id": next_id,
                "name": name,
                "expired": False,
                "size_in_bytes": len(payload),
                "digest": "sha256:" + digest(payload),
                "workflow_run": {"id": run["id"], "head_sha": SHA},
            }
        )
        next_id += 1

    def sealed(
        stage: str, run: dict[str, Any], obj_name: str, obj: dict[str, Any]
    ) -> dict[str, bytes]:
        body = json.dumps(obj).encode()
        env = {
            "version": 1,
            "stage": stage,
            "provenance": {
                "day31_commit": MERGE,
                "day31_run_id": f"{run['id']}:1",
                "day31_source_sha256": SOURCE,
            },
            "files": {obj_name: digest(body)},
        }
        return {"manifest.json": json.dumps(env).encode(), obj_name: body}

    for path, baseline_name, baseline_stage, filename, final_name, final_stage in [
        (
            ".github/workflows/ci.yml",
            "iac-baseline-source",
            "iac-baseline",
            "day31-baseline.json",
            "iac-verified-evidence",
            "iac-evidence",
        ),
        (
            ".github/workflows/runtime.yml",
            "runtime-baseline-source",
            "runtime-baseline",
            "day31-runtime-baseline.json",
            "runtime-verified-evidence",
            "runtime-evidence",
        ),
    ]:
        run = by_path[path]
        baseline = {
            "repository": REPO,
            "event": "pull_request",
            "run_id": run["id"],
            "run_attempt": 1,
            "candidate_sha": MERGE,
            "pr_head_sha": SHA,
            "ref": "refs/pull/16/merge",
            "pr_number": 16,
        }
        add(path, baseline_name, sealed(baseline_stage, run, filename, baseline))
        add(path, final_name, sealed(final_stage, run, "report.json", {"status": "passed"}))

    run35 = by_path[".github/workflows/day35.yml"]
    day35_baseline = {
        "repository": REPO,
        "event": "pull_request",
        "run_id": run35["id"],
        "run_attempt": 1,
        "candidate_sha": MERGE,
        "pr_head_sha": SHA,
        "ref": "refs/pull/16/merge",
        "pr_number": 16,
    }
    add(
        ".github/workflows/day35.yml",
        f"day35-workflow-result-{run35['id']}-1",
        {
            "day35-workflow-result.json": json.dumps(
                {
                    "decision": "READY_FOR_LOCAL_REVIEW",
                    "ci_verified": True,
                    "release_authorized": False,
                    "real_aws_verified": False,
                    "production_apply_enabled": False,
                    "baseline": day35_baseline,
                }
            ).encode()
        },
    )
    run37 = by_path[".github/workflows/day37-aws-staging.yml"]
    add(
        ".github/workflows/day37-aws-staging.yml",
        f"day37-final-{run37['id']}-1",
        {
            "final.json": json.dumps(
                {
                    "mode": "audit",
                    "decision": "READY_FOR_CONFIGURATION_REVIEW",
                    "commit": MERGE,
                    "run_id": str(run37["id"]),
                    "run_attempt": "1",
                    "release_authorized": False,
                    "production_authorized": False,
                    "real_aws_verified": False,
                }
            ).encode()
        },
    )

    fault = by_path[".github/workflows/ci-fault-matrix.yml"]
    for graph in ("iac", "runtime"):
        for case in ("failure", "skipped", "missing-artifact", "tamper", "old-attempt"):
            add(
                ".github/workflows/ci-fault-matrix.yml",
                f"fault-result-{graph}-{case}-1",
                {"fault-result.json": json.dumps(fault_receipt(graph, case, fault)).encode()},
            )

    class FakeGitHub:
        token = "dummy"

        def jobs(self, run_id: int) -> list[dict[str, Any]]:
            run = next(r for r in rows if r["id"] == run_id)
            if run["path"] == ".github/workflows/ci-fault-matrix.yml":
                return [
                    {
                        "name": f"fault ({graph}, {scenario}) / {role}",
                        "status": "completed",
                        "conclusion": (
                            "success"
                            if role == "oracle"
                            else "failure"
                            if role == "consumer"
                            else "skipped"
                            if scenario == "skipped"
                            else "failure"
                            if scenario == "failure"
                            else "success"
                        ),
                    }
                    for graph in ("iac", "runtime")
                    for scenario in (
                        "failure",
                        "skipped",
                        "missing-artifact",
                        "tamper",
                        "old-attempt",
                    )
                    for role in ("producer", "consumer", "oracle")
                ]
            name = d.FINAL_JOBS.get(run["path"])
            if not name:
                return []
            if run["path"] == ".github/workflows/day37-aws-staging.yml":
                return [
                    {"name": name, "conclusion": "success"},
                    {
                        "name": "01 Static contracts and Terraform configuration (no AWS)",
                        "conclusion": "success",
                    },
                    {"name": "03 Saved Plan", "conclusion": "skipped"},
                ]
            return [{"name": name, "conclusion": "success"}]

        def artifacts(self, run_id: int) -> list[dict[str, Any]]:
            return artifact_data.get(run_id, [])

    monkeypatch.setattr(
        d,
        "download_artifact",
        lambda id, token, digest_hash: (
            zip_data[id] if digest(zip_data[id]) == digest_hash else None
        ),
    )
    chosen = selected_runs(rows, SHA, "pull_request", "feat/day38")
    result = d.verify_existing(
        cast(d.GitHub, FakeGitHub()), chosen, SHA, "pull_request", "feat/day38"
    )
    assert result["tested_candidate_sha"] == MERGE
    assert result["source_digest_sha256"] == SOURCE
    assert result["day37_aws_mode"] == "AUDIT_ONLY"


def test_main_branch_governance_must_be_enforced() -> None:
    rules: dict[str, Any] = {
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_last_push_approval": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": "Runtime quality gate", "integration_id": 15368},
                        {"context": "IaC quality gate", "integration_id": 15368},
                    ],
                },
            },
        ],
    }
    verify_main_ruleset(rules)
    with pytest.raises(ValueError, match="bypass"):
        verify_main_ruleset({**rules, "bypass_actors": [{"actor_id": 1}]})
    with pytest.raises(ValueError, match="required statuses"):
        verify_main_ruleset(
            {
                **rules,
                "rules": rules["rules"][:-1]
                + [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "strict_required_status_checks_policy": True,
                            "do_not_enforce_on_create": False,
                            "required_status_checks": [],
                        },
                    }
                ],
            }
        )


def test_fault_matrix_actual_github_jobs_protect_against_forged_receipts() -> None:
    from scripts.day38_readiness import verify_fault_job_matrix

    names = []
    for graph in ("iac", "runtime"):
        for scenario in ("failure", "skipped", "missing-artifact", "tamper", "old-attempt"):
            for role in ("producer", "consumer", "oracle"):
                outcome = (
                    "success"
                    if role == "oracle"
                    else "failure"
                    if role == "consumer"
                    else "skipped"
                    if scenario == "skipped"
                    else "failure"
                    if scenario == "failure"
                    else "success"
                )
                names.append(
                    {
                        "name": f"fault ({graph}, {scenario}) / {role}",
                        "status": "completed",
                        "conclusion": outcome,
                    }
                )
    verify_fault_job_matrix(names)
    with pytest.raises(ValueError, match="missing"):
        verify_fault_job_matrix(names[:-1])
    with pytest.raises(ValueError, match="expected verified state"):
        verify_fault_job_matrix([{**names[0], "conclusion": "success"}, *names[1:]])
    with pytest.raises(ValueError, match="expected verified state"):
        verify_fault_job_matrix([{**names[0], "status": "in_progress"}, *names[1:]])


def test_schedule_evaluates_current_main_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import day38_readiness as d

    class API:
        def get(self, path: str) -> dict[str, Any]:
            if path == "commits/main":
                return {"sha": SHA}
            if path == f"rulesets/{d.MAIN_RULESET_ID}":
                return {}
            raise AssertionError(path)

        def runs(self, candidate: str) -> list[dict[str, Any]]:
            assert candidate == SHA
            return []

    monkeypatch.setattr(d, "verify_main_ruleset", lambda _: None)
    monkeypatch.setattr(d, "selected_runs", lambda *args: {})
    monkeypatch.setattr(d, "verify_existing", lambda *args: {"tested_candidate_sha": SHA})
    monkeypatch.setattr(
        d,
        "verify_day38_offline",
        lambda *args: {"run_id": 11, "run_attempt": 1, "decision": "OFFLINE_AUDIT_PASS"},
    )
    env = {"GITHUB_REPOSITORY": d.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA}
    assert (
        d.evaluate(cast(d.GitHub, API()), "schedule", {"schedule": "17 * * * *"}, env)["decision"]
        == "READY_FOR_STAGING_REVIEW"
    )
    with pytest.raises(ValueError, match="cron"):
        d.evaluate(cast(d.GitHub, API()), "schedule", {"schedule": "* * * * *"}, env)
    with pytest.raises(ValueError, match="default-branch"):
        d.evaluate(
            cast(d.GitHub, API()),
            "schedule",
            {"schedule": "17 * * * *"},
            {**env, "GITHUB_REF": "refs/heads/feature"},
        )

def test_ruleset_accepts_exact_day38_required_check_when_enabled() -> None:
    from scripts import day38_readiness as d

    rules: dict[str, Any] = {
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "require_last_push_approval": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {"context": "Runtime quality gate", "integration_id": 15368},
                        {"context": "IaC quality gate", "integration_id": 15368},
                        {
                            "context": "Day38 offline audit gate (not AWS release)",
                            "integration_id": 15368,
                        },
                    ],
                },
            },
        ],
    }
    d.verify_main_ruleset(rules)
    checks = rules["rules"][-1]["parameters"]["required_status_checks"]
    checks[-1]["integration_id"] = 0
    with pytest.raises(ValueError, match="required statuses"):
        d.verify_main_ruleset(rules)


def test_manual_readiness_job_is_only_dispatched_from_main() -> None:
    import yaml
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[2]
        / ".github/workflows/day38-release-readiness.yml"
    )
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    eligibility = cfg["jobs"]["readiness"]["if"]
    assert "github.event_name == 'workflow_dispatch'" in eligibility
    assert "github.ref == 'refs/heads/main'" in eligibility

