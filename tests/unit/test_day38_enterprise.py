"""Day38 enterprise gates: negative identity and evidence acceptance tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts import day38_enterprise as x


@pytest.mark.parametrize("scenario", x.PROBE_CASES)
def test_every_negative_probe_demonstrates_real_denial(scenario: str) -> None:
    x.probe(scenario)


def context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_REPOSITORY", x.REPO)
    monkeypatch.setenv("GITHUB_RUN_ID", "12")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/9/merge")


def test_candidate_event_is_explicitly_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    context(monkeypatch)
    assert x.source_guard()["release_authorized"] is False
    monkeypatch.setenv("GITHUB_REF", "refs/pull/9/head")
    with pytest.raises(ValueError, match="PR merge ref"):
        x.source_guard()


def test_wrong_repo_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    context(monkeypatch)
    monkeypatch.setenv("GITHUB_REPOSITORY", "attacker/fork")
    with pytest.raises(ValueError, match="repository"):
        x.current_identity()


def test_invalid_run_attempt_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    context(monkeypatch)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "0")
    with pytest.raises(ValueError, match="attempt"):
        x.current_identity()


def test_valid_stage_receipt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    context(monkeypatch)
    proof = tmp_path / "genuine.log"
    proof.write_text("genuine-test-executed\n")
    receipt = tmp_path / "report.json"
    x.stage_report("day38-security", proof, receipt)
    actual = x.load(receipt)
    assert actual["source"]["run_attempt"] == 1
    assert actual["decision"] == "VERIFIED_BY_RUNNER"
    assert actual["release_authorized"] is False
    assert actual["proof_sha256"] == x.raw_sha(proof.read_bytes())


def test_empty_stage_proof_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    context(monkeypatch)
    proof = tmp_path / "empty.log"
    proof.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        x.stage_report("day38-security", proof, tmp_path / "report.json")


def test_unreviewed_stage_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    context(monkeypatch)
    proof = tmp_path / "proof.log"
    proof.write_text("test\n")
    with pytest.raises(ValueError, match="unsupported"):
        x.stage_report("day38-sneaky", proof, tmp_path / "report.json")


def test_missing_stage_aggregate_denied(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    context(monkeypatch)
    (tmp_path / "day38-source").mkdir()
    with pytest.raises(ValueError, match="missing, unknown"):
        x.aggregate(tmp_path, tmp_path / "aggregate.json")


def test_aggregate_with_all_expected_stages_still_needs_real_receipts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context(monkeypatch)
    for stage in x.MANDATORY_STAGES:
        (tmp_path / stage).mkdir()
    with pytest.raises((ValueError, FileNotFoundError)):
        x.aggregate(tmp_path, tmp_path / "aggregate.json")


def test_duplicate_aggregate_json_keys_denied(tmp_path: Path) -> None:
    proof = tmp_path / "fraud.json"
    proof.write_bytes(b'{"decision":"PASS","decision":"BLOCKED"}')
    with pytest.raises(ValueError, match="duplicate"):
        x.load(proof)


def test_missing_mandatory_job_denied() -> None:
    with pytest.raises(ValueError, match="unexpected"):
        x.needs_check({"offline": {"result": "success"}}, {"offline", "evidence"})


@pytest.mark.parametrize("status", ["failure", "skipped", "cancelled", "pending", None])
def test_no_failed_skipped_cancelled_job_passes(status: str | None) -> None:
    with pytest.raises(ValueError, match="mandatory job"):
        x.needs_check({"offline": {"result": status}}, {"offline"})


def test_verify_aggregate_requires_exact_stage_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context(monkeypatch)
    path = tmp_path / "aggregate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "day38.aggregate.v1",
                "decision": "OFFLINE_STAGE_EVIDENCE_VERIFIED",
                "source": x.current_identity(),
                "mandatory_stages": list(x.MANDATORY_STAGES),
                "stages": {},
                "release_authorized": False,
                "aws_plan_or_apply_executed": False,
            }
        )
    )
    with pytest.raises(ValueError, match="aggregate"):
        x.verify_aggregate(path)


def test_final_gate_cannot_fabricate_success_without_upstream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    context(monkeypatch)
    path = tmp_path / "fake.json"
    path.write_text("{}")
    out = tmp_path / "decision.json"
    assert x.final_gate("{}", path, out) == 1
    d = x.load(out)
    assert d["decision"] == "BLOCKED"
    assert d["release_authorized"] is False


def test_workflow_parser_confirms_minimum_enterprise_jobs() -> None:
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    assert file.is_file()
    result = x.verify_workflow_contract(file)
    assert result["job_count"] >= 20
    assert result["aws_authority"] is False
    d = yaml.safe_load(file.read_text())
    assert "workflow_run" in d["on"]
    assert d["concurrency"]["cancel-in-progress"] is False


def test_aws_mutating_workflow_is_rejected(tmp_path: Path) -> None:
    original = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    data: dict[str, Any] = yaml.safe_load(original.read_text())
    data["jobs"]["offline"]["steps"].append(
        {"name": "unsafe", "run": "terraform apply -auto-approve"}
    )
    altered = tmp_path / "unsafe.yml"
    altered.write_text(yaml.safe_dump(data, sort_keys=False))
    with pytest.raises(ValueError, match="Terraform mutation"):
        x.verify_workflow_contract(altered)


def test_unscoped_oidc_permission_rejected(tmp_path: Path) -> None:
    original = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    data: dict[str, Any] = yaml.safe_load(original.read_text())
    data["jobs"]["readiness"]["permissions"]["id-token"] = "write"
    altered = tmp_path / "untrusted.yml"
    altered.write_text(yaml.safe_dump(data, sort_keys=False))
    with pytest.raises(ValueError, match="permissions"):
        x.verify_workflow_contract(altered)


def test_unreviewed_terraform_root_rejected() -> None:
    with pytest.raises(ValueError, match="unreviewed"):
        x.inspect_root("production")


def test_workflow_stage_artifacts_exactly_match_aggregator_inventory() -> None:
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    jobs = yaml.safe_load(file.read_text())["jobs"]
    steps = jobs["evidence"]["steps"]
    downloaded = {
        step["name"].removeprefix("Download independent verified producer ")
        for step in steps
        if step["name"].startswith("Download independent verified producer ")
    }
    assert len(downloaded) == len(x.MANDATORY_STAGES)
    assert downloaded == set(x.MANDATORY_STAGES)
    assert jobs["offline_gate"]["needs"][-1] == "evidence"


def test_trusted_verifier_and_stage_inventory_cannot_drift() -> None:
    from scripts import day38_readiness as verifier

    assert x.MANDATORY_STAGES == verifier.DAY38_REQUIRED_STAGES
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    jobs = yaml.safe_load(file.read_text())["jobs"]
    actual = {
        job["name"]
        for name, job in jobs.items()
        if name
        not in {
            "terraform_roots",
            "terraform_modules",
            "offline",
            "offline_gate",
            "readiness",
            "readiness_gate",
            "diagnostics",
            "post_offline_recheck",
        }
    }
    for root in jobs["terraform_roots"]["strategy"]["matrix"]["root"]:
        actual.add(f"Day38 static AWS Terraform root ({root})")
    for group in jobs["terraform_modules"]["strategy"]["matrix"]["group"]:
        actual.add(f"Day38 Terraform contract group ({group})")
    assert actual == set(verifier.DAY38_REQUIRED_JOB_NAMES)


def test_all_workflow_dependencies_exist_and_cannot_cycle() -> None:
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    jobs = yaml.safe_load(file.read_text())["jobs"]
    for name, job in jobs.items():
        assert set(job.get("needs", [])) <= set(jobs)
        assert name not in job.get("needs", [])

    seen: set[str] = set()
    visiting: set[str] = set()

    def walk(node: str) -> None:
        if node in seen:
            return
        assert node not in visiting, "Dependency cycle in Day38 workflow"
        visiting.add(node)
        for parent in jobs[node].get("needs", []):
            walk(parent)
        visiting.remove(node)
        seen.add(node)

    for name in jobs:
        walk(name)
    assert len(seen) == len(jobs)


def test_end_to_end_22_stage_aggregation_and_final_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sys
    from types import ModuleType

    context(monkeypatch)
    input_root = tmp_path / "input"
    input_root.mkdir()
    for stage in x.MANDATORY_STAGES:
        folder = input_root / stage
        folder.mkdir()
        report = {
            "schema_version": "day38.stage.v1",
            "stage": stage,
            "decision": "VERIFIED_BY_RUNNER",
            "source": x.current_identity(),
            "release_authorized": False,
            "aws_mutation_allowed": False,
            "proof_sha256": "f" * 64,
            "proof_bytes": 12,
        }
        body = json.dumps(report).encode()
        (folder / "receipt.json").write_bytes(body)
        (folder / "manifest.json").write_text(
            json.dumps(
                {
                    "stage": stage,
                    "files": {"receipt.json": x.raw_sha(body)},
                }
            )
        )

    fake_pkg = ModuleType("scripts.iac")
    fake = ModuleType("scripts.iac.pipeline_evidence")

    def verify(folder: Path, stage: str) -> dict[str, str]:
        manifest = x.load(folder / "manifest.json")
        if manifest["stage"] != stage:
            raise ValueError("stage mismatch")
        expect = manifest["files"]["receipt.json"]
        if x.raw_sha((folder / "receipt.json").read_bytes()) != expect:
            raise ValueError("tampered sealed receipt")
        return {"receipt.json": expect}

    fake.verify = verify  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scripts.iac", fake_pkg)
    monkeypatch.setitem(sys.modules, "scripts.iac.pipeline_evidence", fake)

    output = tmp_path / "aggregate.json"
    x.aggregate(input_root, output)
    x.verify_aggregate(output)
    observed = x.load(output)
    assert observed["decision"] == "OFFLINE_STAGE_EVIDENCE_VERIFIED"
    assert len(observed["stages"]) == 22

    gate_jobs = {
        "intake",
        "source_guard",
        "dependencies",
        "python_quality",
        "terraform_format",
        "terraform_roots",
        "terraform_modules",
        "security",
        "policy_tests",
        "trust_tests",
        "recovery_tests",
        "day37_tests",
        "database_tests",
        "ota_tests",
        "fault_probes",
        "workflow_contracts",
        "supply_tests",
        "state_tests",
        "offline",
        "evidence",
    }
    needs = json.dumps({k: {"result": "success"} for k in gate_jobs})
    decision = tmp_path / "decision.json"
    assert x.final_gate(needs, output, decision) == 0
    assert x.load(decision)["decision"] == "OFFLINE_AUDIT_PASS"
    assert x.load(decision)["aws_authorized"] is False

    (input_root / x.MANDATORY_STAGES[-1] / "receipt.json").write_text('{"forged":true}')
    with pytest.raises(ValueError, match="tampered"):
        x.aggregate(input_root, tmp_path / "tampered.json")


def test_single_workflow_has_read_only_protected_main_handoff() -> None:
    root = Path(__file__).resolve().parents[2]
    file = root / ".github/workflows/day38-release-readiness.yml"
    doc = yaml.safe_load(file.read_text())
    assert not (root / ".github/workflows/day38-after-offline.yml").exists()
    assert doc["on"]["workflow_dispatch"]["inputs"]["mode"]["options"] == ["recheck"]
    assert doc["on"]["workflow_dispatch"]["inputs"]["mode"]["default"] == "recheck"
    assert doc["name"] not in doc["on"]["workflow_run"]["workflows"]
    handoff = doc["jobs"]["post_offline_recheck"]
    assert handoff["needs"] == ["offline_gate"]
    assert "github.event_name == 'push'" in handoff["if"]
    assert "github.ref == 'refs/heads/main'" in handoff["if"]
    assert handoff["permissions"] == {"contents": "read", "actions": "read"}
    assert not any("/dispatches" in x.get("run", "") for x in handoff["steps"])
    assert doc["permissions"]["actions"] == "read"
    for job in doc["jobs"].values():
        assert all(v != "write" for v in job.get("permissions", {}).values())
    assert "workflow_dispatch" in doc["jobs"]["readiness"]["if"]
    assert "workflow_dispatch" in doc["jobs"]["readiness_gate"]["if"]
    assert "workflow_dispatch" in doc["jobs"]["offline_gate"]["if"]


def test_recheck_dispatch_must_bind_source_and_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import day38_readiness as verifier

    class API:
        def get(self, path: str) -> dict[str, Any]:
            if path == "commits/main":
                return {"sha": "a" * 40}
            assert path == f"rulesets/{verifier.MAIN_RULESET_ID}"
            return {}

        def runs(self, head: str) -> list[dict[str, Any]]:
            assert head == "a" * 40
            return []

    monkeypatch.setattr(verifier, "verify_main_ruleset", lambda value: None)
    monkeypatch.setattr(verifier, "selected_runs", lambda *args: {})
    monkeypatch.setattr(
        verifier,
        "verify_existing",
        lambda *args: {
            "tested_candidate_sha": "a" * 40,
        },
    )
    monkeypatch.setattr(
        verifier,
        "verify_day38_offline",
        lambda *args: {
            "run_id": 91,
            "run_attempt": 2,
            "decision": "OFFLINE_AUDIT_PASS",
        },
    )
    event: dict[str, Any] = {
        "repository": {"full_name": x.REPO},
        "inputs": {
            "mode": "recheck",
            "source_commit": "a" * 40,
            "source_run_id": "91",
            "source_attempt": "2",
        },
    }
    env = {"GITHUB_REPOSITORY": x.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40}
    assert (
        verifier.evaluate(API(), "workflow_dispatch", event, env)["decision"]
        == "READY_FOR_STAGING_REVIEW"
    )  # type: ignore[arg-type]
    event["inputs"]["source_run_id"] = "90"
    with pytest.raises(ValueError, match="source/run/attempt mismatch"):
        verifier.evaluate(API(), "workflow_dispatch", event, env)  # type: ignore[arg-type]
    event["inputs"]["source_run_id"] = "91"
    event["inputs"]["source_attempt"] = ""
    with pytest.raises(ValueError, match="partial post-offline"):
        verifier.evaluate(API(), "workflow_dispatch", event, env)  # type: ignore[arg-type]
    event["inputs"]["source_attempt"] = "2"
    event["inputs"]["mode"] = "offline"
    with pytest.raises(ValueError, match="read-only recheck"):
        verifier.evaluate(API(), "workflow_dispatch", event, env)  # type: ignore[arg-type]


def test_companion_verifier_requires_exact_latest_day38_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import day38_readiness as verifier

    class API:
        def get(self, path: str) -> dict[str, Any]:
            assert path == f"rulesets/{verifier.MAIN_RULESET_ID}"
            return {}

        def runs(self, head: str) -> list[dict[str, Any]]:
            assert head == "a" * 40
            return []

    monkeypatch.setattr(verifier, "verify_main_ruleset", lambda value: None)
    monkeypatch.setattr(verifier, "selected_runs", lambda *args: {})
    monkeypatch.setattr(
        verifier,
        "verify_existing",
        lambda *args: {
            "tested_candidate_sha": "b" * 40,
        },
    )
    monkeypatch.setattr(
        verifier,
        "verify_day38_offline",
        lambda *args: {
            "run_id": 91,
            "run_attempt": 1,
            "decision": "OFFLINE_AUDIT_PASS",
        },
    )
    event: dict[str, Any] = {
        "repository": {"full_name": x.REPO},
        "workflow_run": {
            "repository": {"full_name": x.REPO},
            "head_sha": "a" * 40,
            "event": "pull_request",
            "head_branch": "feat/day38",
            "status": "completed",
            "path": verifier.DAY38_PATH,
            "id": 91,
            "run_attempt": 1,
            "conclusion": "success",
        },
    }
    env = {"GITHUB_REPOSITORY": x.REPO}
    result = verifier.evaluate(API(), "workflow_run", event, env)  # type: ignore[arg-type]
    assert result["decision"] == "READY_FOR_STAGING_REVIEW"
    assert result["production_authorized"] is False

    event["workflow_run"]["id"] = 92
    with pytest.raises(ValueError, match="superseded"):
        verifier.evaluate(API(), "workflow_run", event, env)  # type: ignore[arg-type]


def test_self_dispatch_waits_for_actual_completed_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import day38_readiness as verifier

    calls = []

    class API:
        def get(self, path: str) -> dict[str, Any]:
            calls.append(path)
            if path == "commits/main":
                return {"sha": "a" * 40}
            assert path == "actions/runs/91"
            status = "in_progress" if len(calls) == 1 else "completed"
            return {
                "id": 91,
                "run_attempt": 2,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "event": "push",
                "path": verifier.DAY38_PATH,
                "name": verifier.DAY38_NAME,
                "status": status,
                "conclusion": "success" if status == "completed" else None,
            }

    monkeypatch.setattr("scripts.day38_readiness.time.sleep", lambda _: None)
    event = {
        "repository": {"full_name": verifier.REPO},
        "inputs": {
            "mode": "recheck",
            "source_commit": "a" * 40,
            "source_run_id": "91",
            "source_attempt": "2",
        },
    }
    env = {
        "GITHUB_REPOSITORY": verifier.REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
    }
    result = verifier.await_offline_completion(
        API(), event, env, max_checks=3, interval=0  # type: ignore[arg-type]
    )
    assert result["decision"] == "OFFLINE_ORIGIN_COMPLETED"
    assert calls == ["actions/runs/91", "actions/runs/91", "commits/main"]


def test_self_dispatch_rejects_failure_and_source_substitution() -> None:
    from scripts import day38_readiness as verifier

    class API:
        def get(self, path: str) -> dict[str, Any]:
            return {
                "id": 91,
                "run_attempt": 2,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "event": "push",
                "path": verifier.DAY38_PATH,
                "name": verifier.DAY38_NAME,
                "status": "completed",
                "conclusion": "failure",
            }

    event = {
        "repository": {"full_name": verifier.REPO},
        "inputs": {
            "mode": "recheck",
            "source_commit": "a" * 40,
            "source_run_id": "91",
            "source_attempt": "2",
        },
    }
    env = {
        "GITHUB_REPOSITORY": verifier.REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
    }
    with pytest.raises(ValueError, match="not complete successfully"):
        verifier.await_offline_completion(
            API(), event, env, max_checks=1, interval=0  # type: ignore[arg-type]
        )
    event["inputs"]["source_commit"] = "b" * 40
    with pytest.raises(ValueError, match="invalid self-dispatched"):
        verifier.await_offline_completion(
            API(), event, env, max_checks=1, interval=0  # type: ignore[arg-type]
        )


def test_gate_baseline_uses_existing_ci_required_path() -> None:
    """The existing scripts.iac.gate reads .iac-reports/day31-baseline.json."""
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    jobs = yaml.safe_load(file.read_text())["jobs"]
    for name in ("terraform_modules", "security", "offline"):
        commands = "\n".join(step.get("run", "") for step in jobs[name]["steps"])
        assert "python -m scripts.iac.ci_baseline_policy" in commands, name
        assert "--output .iac-reports/day31-baseline.json" in commands, name
        assert "python -m scripts.iac.gate" in commands, name
        assert commands.index("--output .iac-reports/day31-baseline.json") < commands.index(
            "python -m scripts.iac.gate"
        ), name


def test_no_write_token_in_pr_editable_single_workflow() -> None:
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    jobs = yaml.safe_load(file.read_text())["jobs"]
    for name, job in jobs.items():
        assert all(value != "write" for value in job.get("permissions", {}).values()), name
        for step in job.get("steps", []):
            assert "/actions/workflows/day38-release-readiness.yml/dispatches" not in step.get(
                "run", ""
            ), name
    assert jobs["post_offline_recheck"]["permissions"]["actions"] == "read"


def test_reviewed_schedule_uses_same_readonly_observer() -> None:
    file = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    d = yaml.safe_load(file.read_text())
    assert d["on"]["schedule"] == [{"cron": "17 * * * *"}]
    assert "github.event_name == 'schedule'" in d["jobs"]["readiness"]["if"]
    assert "github.event_name == 'schedule'" in d["jobs"]["readiness_gate"]["if"]


def test_privileged_job_mutation_cannot_pass_static_contract(tmp_path: Path) -> None:
    original = Path(__file__).resolve().parents[2] / ".github/workflows/day38-release-readiness.yml"
    d = yaml.safe_load(original.read_text())
    d["jobs"]["post_offline_recheck"]["permissions"]["actions"] = "write"
    mutated = tmp_path / "changed.yml"
    mutated.write_text(yaml.safe_dump(d, sort_keys=False))
    with pytest.raises(ValueError, match="write permissions"):
        x.verify_workflow_contract(mutated)
