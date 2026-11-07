"""High-risk DAG + saved-plan/integrity/read-only checks."""

import re
from pathlib import Path
from typing import Any, cast

import yaml

from scripts import day37_gate

ROOT = Path(__file__).resolve().parents[2]
W = yaml.safe_load((ROOT / ".github/workflows/day37-aws-staging.yml").read_text())


def workflow_jobs() -> dict[str, Any]:
    return cast(dict[str, Any], W["jobs"])


def test_approval_after_plan_not_before() -> None:
    jobs = workflow_jobs()
    assert "plan" in jobs["bootstrap"]["needs"]
    assert "deploy_plan" in jobs["deploy"]["needs"]
    assert jobs["bootstrap"]["environment"] == "aws-staging-bootstrap"
    assert jobs["deploy"]["environment"] == "aws-staging-deploy"
    assert jobs["deploy_plan"]["environment"] == "aws-staging-plan"
    assert "Plan ${{ needs.deploy_plan.outputs.plan_sha256 }}" in jobs["deploy"]["name"]


def test_saved_plan_applied_without_regeneration() -> None:
    for job in ("bootstrap", "deploy"):
        text = "\n".join(x.get("run", "") for x in workflow_jobs()[job]["steps"])
        assert "day37_plan_transport fetch" in text
        assert 'terraform -chdir="${DAY37_TF_ROOT}" apply' in text
        assert 'terraform -chdir="${DAY37_TF_ROOT}" plan ' not in text
    assert "day37_fence mark --phase deploy" in text
    assert text.index("day37_fence mark --phase deploy") < text.index('terraform -chdir="${DAY37_TF_ROOT}" apply')


def test_private_plan_never_uploaded_as_github_artifact() -> None:
    for name in ("plan", "deploy_plan"):
        for step in workflow_jobs()[name]["steps"]:
            if "actions/upload-artifact@" in step.get("uses", ""):
                assert step["with"]["path"] == ".day37/plan-public/"


def test_success_requires_closure_and_failure_keeps_fence() -> None:
    jobs = workflow_jobs()
    assert "close" in jobs["gate"]["needs"]
    assert "verify" in jobs["close"]["needs"]
    text = "\n".join(x.get("run", "") for x in jobs["close"]["steps"])
    assert "-detailed-exitcode" in text and "day37_fence close" in text
    assert "day37_fence close" not in "\n".join(x.get("run", "") for x in jobs["recovery"]["steps"])


def test_plan_check_scope_refuses_iam_updates() -> None:
    plan = {
        "variables": {"enable_service": {"value": False}},
        "resource_changes": [
            {
                "address": "aws_iam_role.staging",
                "type": "aws_iam_role",
                "change": {"actions": ["update"]},
            }
        ],
    }
    import pytest

    with pytest.raises(ValueError, match="Bootstrap refuses"):
        day37_gate.plan_check(plan, phase="bootstrap")


def test_foundation_requires_private_alb_and_encryption() -> None:
    text = (ROOT / "infra/terraform/environments/ota-staging-foundation/main.tf").read_text()
    for key in ("internal", "manage_master_user_password", "transit_encryption_enabled"):
        assert re.search(rf"(?m)^\s*{key}\s*=\s*true\s*$", text) is not None
    assert "auth_token_wo" in text
    assert 'oidc_application_provisioned" { value = false' in text
