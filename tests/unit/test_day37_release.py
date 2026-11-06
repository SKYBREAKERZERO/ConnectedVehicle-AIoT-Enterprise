"""Synthetic policy contracts, explicitly not live AWS/signature/review evidence."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.day36_staging import ROOT
from scripts.day37_release import CASES, PHASES, contract_errors, gate, provenance, redact_guard


@pytest.fixture(scope="module", autouse=True)
def stamp(record_testsuite_property: Callable[[str, str], None]) -> None:
    for key, value in provenance().items():
        record_testsuite_property(key, value)


def reference(phase: str) -> dict[str, Any]:
    values: dict[str, dict[str, Any]] = {
        "admission": {
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "commit": "a" * 40,
            "approved_commit": "a" * 40,
            "approved": True,
            "reviewer": "independent-fixture",
            "requester": "author-fixture",
            "attempt": 1,
            "evidence_attempt": 1,
        },
        "artifact": {
            "registry_manifest_digest": "sha256:" + "a" * 64,
            "ecr_observed_digest": "sha256:" + "a" * 64,
            "identity_kind": "registry-manifest",
            "signature_valid": True,
            "sbom_bound": True,
        },
        "identity": {
            "account": "111122223333",
            "expected_account": "111122223333",
            "region": "ap-northeast-1",
            "sub": ("repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:aws-staging"),
            "aud": "sts.amazonaws.com",
            "role_arn": "arn:aws:iam::111122223333:role/connected-vehicle-ota-staging-github",
        },
        "plan": {
            "plan_bound": True,
            "destroy_count": 0,
            "contains_secret_value": False,
            "contains_state": False,
        },
        "deploy": {"live_execution_enabled": False, "uses_aws_credentials": False},
        "rollback": {
            "rollback_state": "COMPLETED",
            "previous_state": "COMPLETED",
            "schema_before": "b16f238d45ac",
            "schema_after": "b16f238d45ac",
            "command_count": 1,
            "outbox_count": 1,
            "ecu_security_before": 2,
            "ecu_security_after": 2,
        },
    }
    return deepcopy(values[phase])


def deny(phase: str, case: str) -> None:
    data = reference(phase)
    changes: dict[str, dict[str, tuple[str, Any]]] = {
        "admission": {
            "pr": ("event", "pull_request"),
            "branch": ("ref", "refs/heads/feature"),
            "sha": ("commit", "b" * 40),
            "self-review": ("reviewer", "author-fixture"),
            "unapproved": ("approved", False),
            "attempt": ("attempt", 2),
        },
        "artifact": {
            "tag": ("registry_manifest_digest", "api:latest"),
            "local-id": ("identity_kind", "local-image-id"),
            "digest": ("ecr_observed_digest", "sha256:" + "b" * 64),
            "unsigned": ("signature_valid", False),
            "missing-sbom": ("sbom_bound", False),
        },
        "identity": {
            "account": ("account", "999988887777"),
            "region": ("region", "us-east-1"),
            "subject": ("sub", "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:pull_request"),
            "audience": ("aud", "wrong-audience"),
            "production-role": ("role_arn", "arn:aws:iam::111122223333:role/production"),
        },
        "plan": {
            "destroy": ("destroy_count", 1),
            "secret": ("contains_secret_value", True),
            "state": ("contains_state", True),
            "missing-plan": ("plan_bound", False),
        },
        "deploy": {
            "enabled": ("live_execution_enabled", True),
            "credentials": ("uses_aws_credentials", True),
        },
        "rollback": {
            "failed": ("rollback_state", "FAILED"),
            "schema": ("schema_after", "different"),
            "uncompleted-old": ("previous_state", "IN_PROGRESS"),
            "duplicate-command": ("command_count", 2),
            "ecu-floor": ("ecu_security_after", 1),
        },
    }
    key, value = changes[phase][case]
    data[key] = value
    assert contract_errors(phase, data)


@pytest.mark.parametrize("case", CASES["admission"])
def test_admission_denies_invalid_request(case: str) -> None:
    deny("admission", case)


@pytest.mark.parametrize("case", CASES["artifact"])
def test_artifact_denies_invalid_request(case: str) -> None:
    deny("artifact", case)


@pytest.mark.parametrize("case", CASES["identity"])
def test_identity_denies_invalid_request(case: str) -> None:
    deny("identity", case)


@pytest.mark.parametrize("case", CASES["plan"])
def test_plan_denies_invalid_request(case: str) -> None:
    deny("plan", case)


@pytest.mark.parametrize("case", CASES["deploy"])
def test_deploy_denies_invalid_request(case: str) -> None:
    deny("deploy", case)


@pytest.mark.parametrize("case", CASES["rollback"])
def test_rollback_denies_invalid_request(case: str) -> None:
    deny("rollback", case)


def test_reference_shapes_are_contracts_without_execution_authority() -> None:
    for phase in PHASES:
        assert contract_errors(phase, reference(phase)) == []
    workflow = yaml.safe_load((ROOT / ".github/workflows/day37-staging.yml").read_text())
    assert set(workflow["jobs"]) == set(PHASES) | {"gate"}
    for name, job in workflow["jobs"].items():
        assert set(job.get("needs", [])) <= set(workflow["jobs"])
        commands = "\n".join(s.get("run", "") for s in job["steps"])
        assert "aws ecs" not in commands and "terraform apply" not in commands
        assert "docker push" not in commands and "configure-aws-credentials" not in str(job)
        if name == "gate":
            assert set(job["needs"]) == set(PHASES) and "always()" in job["if"]
    assert all(value == "read" for value in workflow["permissions"].values())


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "secret_value",
        "aws_access_key",
        "session_token",
        "terraform_tfstate",
        "raw_plan",
        "raw_log",
    ],
)
def test_sensitive_evidence_is_rejected(key: str) -> None:
    with pytest.raises(ValueError):
        redact_guard({"nested": {key: "synthetic-secret"}})


def test_gate_rejects_missing_evidence_even_when_jobs_claim_success(tmp_path: Path) -> None:
    with pytest.raises((ValueError, OSError)):
        gate(tmp_path, {phase: {"result": "success"} for phase in PHASES})
