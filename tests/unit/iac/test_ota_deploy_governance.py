"""Offline trust/admission negatives, not signed OIDC or live AWS authorization tests."""

from __future__ import annotations

import importlib
import os
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import pytest

from scripts.iac.deploy_governance import (
    READ_ACTIONS,
    REPOSITORY,
    ROOT,
    SUBJECT,
    deployment_context_errors,
    environment_errors,
    load_workflow,
    oidc_claim_errors,
    preview_policy_errors,
    quality_errors,
    run_identity,
    source_digest,
    static_evidence,
    workflow_errors,
)
from scripts.iac.plan_policy import evaluate

ACCOUNT = "123456789012"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
BUCKETS = {"arn:aws:s3:::cv-ota-production-firmware"}


@pytest.fixture(scope="module", autouse=True)
def governance_stamp(record_testsuite_property: Callable[[str, object], None]) -> None:
    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    )
    for name, value in {
        "day25_commit": commit,
        "day25_run_id": run_identity(),
        "day25_source_sha256": source_digest(),
    }.items():
        record_testsuite_property(name, value)


def context() -> dict[str, Any]:
    return {
        "event": "workflow_dispatch",
        "repository": REPOSITORY,
        "ref": "refs/heads/main",
        "ref_protected": True,
        "commit": "a" * 40,
        "head_commit": "a" * 40,
        "mode": "dry-run",
    }


def environment() -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        {
            "name": "production",
            "can_admins_bypass": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"login": "SKYBREAKERZERO"}}],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        },
        {"branch_policies": [{"name": "main", "type": "branch"}]},
    )


def policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": sorted(READ_ACTIONS),
                "Resource": sorted(BUCKETS),
                "Condition": {"StringEquals": {"aws:ResourceAccount": ACCOUNT}},
            }
        ],
    }


def runs() -> list[dict[str, Any]]:
    return [
        {
            "id": index,
            "run_attempt": 1,
            "path": f".github/workflows/{name}.yml",
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "event": "push",
            "head_repository": {"full_name": REPOSITORY},
            "updated_at": "2026-10-26T00:00:00Z",
        }
        for index, name in enumerate(("ci", "runtime"), 10)
    ]


def test_reviewed_preview_contract_passes() -> None:
    assert not workflow_errors(load_workflow())
    assert not deployment_context_errors(context())
    assert not environment_errors(*environment())
    assert not preview_policy_errors(policy(), ACCOUNT, BUCKETS)
    assert not quality_errors(runs(), "a" * 40)
    assert not oidc_claim_errors(
        {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "sts.amazonaws.com",
            "sub": SUBJECT,
        },
        account=ACCOUNT,
        provider=PROVIDER,
    )


def test_ci_does_not_hold_deployment_identity() -> None:
    yaml = importlib.import_module("yaml")
    for name in ("ci", "runtime"):
        raw = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
        workflow = yaml.load(raw, Loader=yaml.BaseLoader)
        assert workflow["permissions"] == {"contents": "read"}
        assert "secrets." not in raw and "aws-actions/configure-aws-credentials" not in raw
        for job in workflow["jobs"].values():
            assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}


@pytest.mark.parametrize("event", ("pull_request", "pull_request_target", "workflow_run", "push"))
def test_pr_cannot_request_deployment(event: str) -> None:
    request = context()
    request["event"] = event
    # Even a matching environment subject cannot replace branch/event admission.
    assert deployment_context_errors(request)


@pytest.mark.parametrize(
    "violation", ("subject", "pr_subject", "audience", "issuer", "account", "provider")
)
def test_oidc_subject_audience_and_account_rejected(violation: str) -> None:
    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "sts.amazonaws.com",
        "sub": SUBJECT,
    }
    account, provider = ACCOUNT, PROVIDER
    if violation == "subject":
        claims["sub"] = "repo:attacker/fork:environment:production"
    elif violation == "pr_subject":
        claims["sub"] = f"repo:{REPOSITORY}:pull_request"
    elif violation == "audience":
        claims["aud"] = "attacker"
    elif violation == "issuer":
        claims["iss"] = "https://attacker.example"
    elif violation == "account":
        account = "000000000000"
    else:
        provider = "arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com"
    assert oidc_claim_errors(claims, account=account, provider=provider)


@pytest.mark.parametrize(
    "violation",
    ("no_reviewers", "self_review", "admin_bypass", "wildcard_branch", "tag", "wrong_environment"),
)
def test_unapproved_or_unprotected_environment_rejected(violation: str) -> None:
    settings, branches = environment()
    if violation == "no_reviewers":
        settings["protection_rules"] = []
    elif violation == "self_review":
        settings["protection_rules"][0]["prevent_self_review"] = False
    elif violation == "admin_bypass":
        settings["can_admins_bypass"] = True
    elif violation == "wildcard_branch":
        branches["branch_policies"][0]["name"] = "*"
    elif violation == "tag":
        branches["branch_policies"][0]["type"] = "tag"
    else:
        settings["name"] = "staging"
    assert environment_errors(settings, branches)


@pytest.mark.parametrize(
    "field,value",
    (
        ("ref", "refs/heads/feature"),
        ("ref", "refs/tags/main"),
        ("ref_protected", False),
        ("repository", "attacker/fork"),
        ("commit", "b" * 40),
        ("commit", "HEAD; echo unsafe"),
    ),
)
def test_non_main_source_rejected(field: str, value: Any) -> None:
    request = context()
    request[field] = value
    assert deployment_context_errors(request)


@pytest.mark.parametrize("self_asserted_approval", (True, False))
def test_apply_is_never_authorized(self_asserted_approval: bool) -> None:
    request = context()
    request.update(mode="apply", approved=self_asserted_approval)
    assert deployment_context_errors(request)


@pytest.mark.parametrize(
    "violation",
    (
        "action_wildcard",
        "resource_wildcard",
        "pass_role",
        "write",
        "cross_account",
        "extra_statement",
    ),
)
def test_dangerous_identity_permissions_rejected(violation: str) -> None:
    document = policy()
    statement = document["Statement"][0]
    if violation == "action_wildcard":
        statement["Action"] = ["s3:*"]
    elif violation == "resource_wildcard":
        statement["Resource"] = ["*"]
    elif violation == "pass_role":
        statement["Action"].append("iam:PassRole")
    elif violation == "write":
        statement["Action"].append("s3:PutObject")
    elif violation == "cross_account":
        statement["Condition"]["StringEquals"]["aws:ResourceAccount"] = "999999999999"
    else:
        document["Statement"].append(deepcopy(statement))
    assert preview_policy_errors(document, ACCOUNT, BUCKETS)


@pytest.mark.parametrize("actions", (["delete"], ["delete", "create"], ["forget"]))
def test_destroy_is_rejected(actions: list[str]) -> None:
    plan = {
        "format_version": "1.2",
        "complete": True,
        "planned_values": {"root_module": {}},
        "resource_changes": [
            {
                "address": "aws_iam_role.protected",
                "type": "aws_iam_role",
                "change": {"actions": actions, "before": {}, "after": None},
            }
        ],
    }
    assert any("prohibited" in error for error in evaluate(plan))


@pytest.mark.parametrize(
    "violation",
    (
        "pr_trigger",
        "oidc_token",
        "no_environment",
        "apply_command",
        "untrusted_checkout",
        "stored_secret",
        "aws_action",
        "skip_guard",
    ),
)
def test_workflow_privilege_escalation_rejected(violation: str) -> None:
    workflow = load_workflow()
    job = workflow["jobs"]["dry_run"]
    if violation == "pr_trigger":
        workflow["on"]["pull_request"] = {}
    elif violation == "oidc_token":
        job["permissions"] = {"contents": "read", "id-token": "write"}
    elif violation == "no_environment":
        del job["environment"]
    elif violation == "apply_command":
        job["steps"][2]["run"] = "terraform apply -auto-approve"
    elif violation == "untrusted_checkout":
        job["steps"][0]["with"]["ref"] = "${{ inputs.release_commit }}"
    elif violation == "stored_secret":
        job["steps"][2]["env"]["AWS_ACCESS_KEY_ID"] = "${{ secrets.AWS_ACCESS_KEY_ID }}"
    elif violation == "aws_action":
        job["steps"].append({"uses": "aws-actions/configure-aws-credentials@" + "a" * 40})
    else:
        job["if"] = "false"
    assert workflow_errors(workflow)


@pytest.mark.parametrize(
    "kind", ("new_run", "rerun_older_id", "in_progress", "wrong_workflow", "wrong_commit")
)
def test_latest_quality_failure_cannot_reuse_older_success(kind: str) -> None:
    evidence = runs()
    newer = dict(evidence[0], id=20, conclusion="failure", updated_at="2026-10-26T01:00:00Z")
    if kind == "rerun_older_id":
        newer.update(id=5, run_attempt=2)
    elif kind == "in_progress":
        newer.update(status="in_progress", conclusion=None)
    elif kind == "wrong_workflow":
        evidence[0]["path"] = ".github/workflows/imposter.yml"
        newer["path"] = ".github/workflows/imposter.yml"
    elif kind == "wrong_commit":
        evidence[0]["head_sha"] = "b" * 40
        newer["head_sha"] = "b" * 40
    evidence.append(newer)
    assert quality_errors(evidence, "a" * 40)


@pytest.mark.parametrize("violation", ("global_env", "job_env", "runner", "unscoped_upload"))
def test_ambient_execution_defaults_are_rejected(violation: str) -> None:
    workflow = load_workflow()
    if violation == "global_env":
        workflow["env"] = {"BASH_ENV": "/tmp/untrusted"}
    elif violation == "job_env":
        workflow["jobs"]["dry_run"]["env"] = {"BASH_ENV": "/tmp/untrusted"}
    elif violation == "runner":
        workflow["jobs"]["dry_run"]["runs-on"] = "self-hosted"
    else:
        workflow["jobs"]["dry_run"]["steps"][-1]["with"]["path"] = "/tmp"
    assert workflow_errors(workflow)


@pytest.mark.parametrize(
    "violation", ("wrong_run", "duplicate_property", "missing_test", "skipped", "root")
)
def test_governance_evidence_cannot_hide_failures_or_relabel_a_run(
    tmp_path: Path, violation: str
) -> None:
    from scripts.iac.deploy_governance import GOVERNANCE_TESTS

    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    )
    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite")
    properties = ElementTree.SubElement(suite, "properties")
    stamp = {
        "day25_commit": commit,
        "day25_run_id": run_identity(),
        "day25_source_sha256": source_digest(),
    }
    if violation == "wrong_run":
        stamp["day25_run_id"] = "old-run:1"
    for name, value in stamp.items():
        ElementTree.SubElement(properties, "property", name=name, value=value)
    for name in sorted(GOVERNANCE_TESTS):
        ElementTree.SubElement(suite, "testcase", name=name)
    if violation == "duplicate_property":
        properties.append(deepcopy(properties[0]))
    elif violation == "missing_test":
        suite.remove(suite.findall("testcase")[0])
    elif violation == "skipped":
        ElementTree.SubElement(suite.findall("testcase")[0], "skipped")
    elif violation == "root":
        root.tag = "unknown"
    target = tmp_path / "evidence.xml"
    target.write_bytes(ElementTree.tostring(root))
    expected = {
        "wrong_run": "attestation",
        "duplicate_property": "attestation",
        "missing_test": "Mandatory",
        "skipped": "Failed/skipped",
        "root": "Invalid",
    }
    with pytest.raises(ValueError, match=expected[violation]):
        static_evidence(target)
