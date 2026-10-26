"""Day25: fail-closed release admission and offline governance evidence, never AWS Apply."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree

from scripts.iac.plan_policy import policy_errors

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
SUBJECT = f"repo:{REPOSITORY}:environment:production"
READ_ACTIONS = {
    "s3:GetBucketLocation",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketPublicAccessBlock",
}
PINS = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
}
COMMAND = (
    'python -m scripts.iac.deploy_governance --preflight --commit "$TARGET_SHA" --mode "$MODE"'
)
REQUIRED_TESTS = {
    "test_pr_cannot_request_deployment",
    "test_oidc_subject_audience_and_account_rejected",
    "test_unapproved_or_unprotected_environment_rejected",
    "test_non_main_source_rejected",
    "test_apply_is_never_authorized",
    "test_dangerous_identity_permissions_rejected",
    "test_destroy_is_rejected",
    "test_workflow_privilege_escalation_rejected",
    "test_latest_quality_failure_cannot_reuse_older_success",
    "test_ci_does_not_hold_deployment_identity",
}
GOVERNANCE_TESTS = REQUIRED_TESTS | {
    "test_reviewed_preview_contract_passes",
    "test_ambient_execution_defaults_are_rejected",
    "test_governance_evidence_cannot_hide_failures_or_relabel_a_run",
}


def source_digest() -> str:
    paths = [
        ROOT / p
        for p in (
            ".github/workflows/ci.yml",
            ".github/workflows/runtime.yml",
            ".github/workflows/ota-aws-deploy.yml",
            "scripts/iac/deploy_governance.py",
            "tests/unit/iac/test_ota_deploy_governance.py",
        )
    ]
    paths.extend((ROOT / "infra/terraform/modules/github-oidc-deploy").rglob("*.tf"))
    paths.extend((ROOT / "infra/terraform/modules/github-oidc-deploy").rglob("*.tftest.hcl"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def oidc_claim_errors(claims: dict[str, Any], *, account: str, provider: str) -> list[str]:
    """Synthetic policy checks only. This does not verify a JWT signature or call STS."""
    if (
        re.fullmatch(r"[0-9]{12}", account) is None
        or account == "000000000000"
        or provider != f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"
        or claims.get("iss") != "https://token.actions.githubusercontent.com"
        or claims.get("aud") != "sts.amazonaws.com"
        or claims.get("sub") != SUBJECT
    ):
        return ["OIDC issuer, audience, subject or provider account is outside the trust contract"]
    return []


def preview_policy_errors(policy: dict[str, Any], account: str, buckets: set[str]) -> list[str]:
    errors = policy_errors(policy)
    try:
        statements = policy["Statement"]
        statement = statements[0]
        if (
            policy["Version"] != "2012-10-17"
            or len(statements) != 1
            or statement["Effect"] != "Allow"
            or set(statement["Action"]) != READ_ACTIONS
            or set(statement["Resource"]) != buckets
            or statement["Condition"] != {"StringEquals": {"aws:ResourceAccount": account}}
            or any(field in statement for field in ("NotAction", "NotResource", "Principal"))
            or not buckets
            or any(
                re.fullmatch(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", b) is None
                for b in buckets
            )
        ):
            errors.append(
                "Preview identity/boundary must permit only exact account-owned metadata reads"
            )
    except (KeyError, TypeError, IndexError):
        errors.append("Missing or malformed preview permissions")
    return errors


def environment_errors(environment: dict[str, Any], branches: dict[str, Any]) -> list[str]:
    try:
        reviewers = [
            r for r in environment["protection_rules"] if r["type"] == "required_reviewers"
        ]
        if (
            environment["name"] != "production"
            or environment.get("can_admins_bypass") is not False
            or len(reviewers) != 1
            or not reviewers[0]["reviewers"]
            or reviewers[0].get("prevent_self_review") is not True
            or environment["deployment_branch_policy"]
            != {"protected_branches": False, "custom_branch_policies": True}
            or [{"name": p["name"], "type": p["type"]} for p in branches["branch_policies"]]
            != [{"name": "main", "type": "branch"}]
        ):
            return [
                "Production requires independent review, no admin bypass and exact main branch rule"
            ]
    except (KeyError, TypeError):
        return ["Production Environment evidence is incomplete"]
    return []


def deployment_context_errors(context: dict[str, Any]) -> list[str]:
    if (
        context.get("event") != "workflow_dispatch"
        or context.get("repository") != REPOSITORY
        or context.get("ref") != "refs/heads/main"
        or context.get("ref_protected") is not True
        or context.get("mode") != "dry-run"
        or re.fullmatch(r"[0-9a-f]{40}", str(context.get("commit", ""))) is None
        or context.get("commit") != context.get("head_commit")
    ):
        return [
            "Only an exact protected main dispatch may perform a dry run; AWS Apply is disabled"
        ]
    return []


def quality_errors(runs: list[dict[str, Any]], commit: str) -> list[str]:
    errors = []
    for path in (".github/workflows/ci.yml", ".github/workflows/runtime.yml"):
        matching = [r for r in runs if r.get("path") == path and r.get("head_sha") == commit]
        try:
            stamps = [
                datetime.fromisoformat(r["updated_at"].replace("Z", "+00:00")) for r in matching
            ]
            if any(stamp.utcoffset() is None for stamp in stamps):
                raise ValueError("Unbound quality timestamp")
            latest = max(
                matching,
                key=lambda r: (r["updated_at"], int(r["id"]), int(r["run_attempt"])),
                default=None,
            )
        except (KeyError, TypeError, ValueError):
            errors.append(f"Invalid quality-run revision/time metadata: {path}")
            continue
        if (
            latest is None
            or latest.get("status") != "completed"
            or latest.get("conclusion") != "success"
            or latest.get("head_branch") != "main"
            or latest.get("event") not in {"push", "workflow_dispatch"}
            or latest.get("head_repository", {}).get("full_name") != REPOSITORY
        ):
            errors.append(f"Latest exact-source main quality run is not successful: {path}")
    return errors


def workflow_errors(workflow: dict[str, Any]) -> list[str]:
    try:
        if set(workflow) - {"name", "on", "permissions", "concurrency", "jobs"}:
            return ["Unreviewed global workflow environment or execution defaults"]
        if set(workflow["on"]) != {"workflow_dispatch"}:
            return ["Deployment entry point must be manual only"]
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        if (
            set(inputs) != {"release_commit", "mode"}
            or inputs["release_commit"].get("required") != "true"
        ):
            return ["An explicit immutable release commit is required"]
        if inputs["mode"]["options"] != ["dry-run"] or inputs["mode"]["default"] != "dry-run":
            return ["The workflow must not offer Apply"]
        permissions = {"contents": "read", "actions": "read"}
        if workflow["permissions"] != permissions or set(workflow["jobs"]) != {
            "preflight",
            "dry_run",
        }:
            return ["Only read-only preflight and protected preview jobs are allowed"]
        if "secrets." in json.dumps(workflow):
            return ["Deployment skeleton must not consume stored credentials"]
        jobs = workflow["jobs"]
        if (
            jobs["dry_run"]["environment"] != "production"
            or jobs["dry_run"]["needs"] != "preflight"
        ):
            return ["The preview must wait for preflight and production Environment approval"]
        for job in jobs.values():
            if set(job) - {"runs-on", "timeout-minutes", "steps", "needs", "environment"}:
                return ["Unreviewed job execution environment"]
            if (
                job.get("permissions", permissions) != permissions
                or job["runs-on"] != "ubuntu-24.04"
            ):
                return ["Workflow tokens/runners exceed the reviewed contract"]
            if "if" in job or "continue-on-error" in job:
                return ["Release admission must not be skipped or soft-failed"]
            commands = 0
            for step in job["steps"]:
                if set(step) - {"name", "uses", "with", "run", "env"}:
                    return ["Unreviewed step execution controls"]
                if "if" in step or "continue-on-error" in step:
                    return ["Deployment steps must not bypass checks"]
                if "uses" in step:
                    if "env" in step or "run" in step:
                        return ["Actions must not introduce ambient execution credentials"]
                    if step["uses"] not in PINS:
                        return ["Unreviewed action or AWS credential action"]
                    if step["uses"].startswith("actions/checkout@") and step["with"] != {
                        "ref": "${{ github.sha }}",
                        "persist-credentials": "false",
                    }:
                        return [
                            "Checkout must use the immutable workflow commit "
                            "without persistent credentials"
                        ]
                    if step["uses"].startswith("actions/setup-python@") and step["with"] != {
                        "python-version": "3.12"
                    }:
                        return ["Unreviewed Python runtime"]
                elif step.get("run") == COMMAND:
                    commands += 1
                    if step["env"] != {
                        "GH_TOKEN": "${{ github.token }}",
                        "TARGET_SHA": "${{ inputs.release_commit }}",
                        "MODE": "${{ inputs.mode }}",
                    }:
                        return [
                            "Untrusted release input must only pass through environment variables"
                        ]
                else:
                    return ["Unreviewed command, Terraform Apply or credential operation"]
            if commands != 1:
                return ["Every job must recheck admission, including after approval"]
        uploads = [
            s
            for s in jobs["dry_run"]["steps"]
            if s.get("uses", "").startswith("actions/upload-artifact@")
        ]
        if len(uploads) != 1 or uploads[0]["with"] != {
            "name": "day25-protected-dry-run",
            "path": ".iac-reports/day25-dry-run.json",
            "include-hidden-files": "true",
            "if-no-files-found": "error",
        }:
            return ["Protected preview evidence must be mandatory and narrowly scoped"]
    except (KeyError, TypeError, AttributeError):
        return ["Missing or malformed deployment workflow"]
    return []


def load_workflow() -> dict[str, Any]:
    # Import only for offline checks; the deployment skeleton uses standard library only.
    yaml = importlib.import_module("yaml")

    return cast(
        dict[str, Any],
        yaml.load(
            (ROOT / ".github/workflows/ota-aws-deploy.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        ),
    )


def gh(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path], check=True, capture_output=True, text=True, timeout=30
    )
    return json.loads(result.stdout)


def preflight(commit: str, mode: str) -> dict[str, Any]:
    context = {
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "ref": os.environ.get("GITHUB_REF"),
        "ref_protected": os.environ.get("GITHUB_REF_PROTECTED") == "true",
        "head_commit": os.environ.get("GITHUB_SHA"),
        "commit": commit,
        "mode": mode,
    }
    errors = deployment_context_errors(context)
    if errors:
        raise ValueError("; ".join(errors))
    base = f"repos/{REPOSITORY}"
    environment = gh(base + "/environments/production")
    branches = gh(base + "/environments/production/deployment-branch-policies")
    errors.extend(environment_errors(environment, branches))
    branch = gh(base + "/branches/main")
    if branch.get("protected") is not True or branch.get("commit", {}).get("sha") != commit:
        errors.append("Main protection or current release revision changed")
    runs: list[dict[str, Any]] = []
    for page in range(1, 101):
        batch = gh(base + f"/actions/runs?head_sha={commit}&per_page=100&page={page}")[
            "workflow_runs"
        ]
        runs.extend(batch)
        if len(batch) < 100:
            break
    else:
        errors.append("Quality-run enumeration was truncated")
    errors.extend(quality_errors(runs, commit))
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "mode": "dry-run",
        "commit": commit,
        "run_id": run_identity(),
        "environment": "production",
        "environment_settings_verified": True,
        "production_apply_enabled": False,
        "aws_credentials_requested": False,
        "aws_sts_verified": False,
    }


def run_identity() -> str:
    return (
        os.environ.get("GITHUB_RUN_ID", "local") + ":" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    )


def static_evidence(xml: Path) -> dict[str, Any]:
    errors = workflow_errors(load_workflow())
    if errors:
        raise ValueError("; ".join(errors))
    commit = (
        os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    )
    digest = source_digest()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or not run_identity().strip():
        raise ValueError("Governance requires full source and run identity")
    raw = xml.read_bytes()
    if len(raw) > 2_000_000 or b"<!DOCTYPE" in raw.upper():
        raise ValueError("Invalid governance XML")
    document = ElementTree.fromstring(raw)
    if document.tag not in {"testsuite", "testsuites"}:
        raise ValueError("Invalid governance XML root")
    if any(document.findall(f".//{tag}") for tag in ("failure", "error", "skipped")) or any(
        int(suite.attrib.get(field, "0")) != 0
        for suite in document.iter()
        if suite.tag in {"testsuite", "testsuites"}
        for field in ("failures", "errors", "skipped")
    ):
        raise ValueError("Failed/skipped governance test evidence")
    cases = [
        case
        for case in document.findall(".//testcase")
        if case.attrib["name"].split("[", 1)[0] in GOVERNANCE_TESTS
    ]
    names = {case.attrib["name"].split("[", 1)[0] for case in cases}
    if names != GOVERNANCE_TESTS or len({case.attrib["name"] for case in cases}) != len(cases):
        raise ValueError("Mandatory negative governance cases are missing")
    properties = document.findall(".//testsuite/properties/property")
    stamp = {p.attrib["name"]: p.attrib["value"] for p in properties}
    if len(stamp) != len(properties) or any(
        stamp.get(key) != value
        for key, value in {
            "day25_commit": commit,
            "day25_run_id": run_identity(),
            "day25_source_sha256": digest,
        }.items()
    ):
        raise ValueError("Governance test-time source/run attestation mismatch")
    return {
        "version": 1,
        "mode": "static-contracts",
        "environment": "production",
        "provenance": {
            "commit": commit,
            "run_id": run_identity(),
            "governance_source_sha256": digest,
        },
        "governance_contracts": sorted(names),
        "required_negative_contracts": sorted(REQUIRED_TESTS),
        "security_test_cases": len(cases),
        "junit_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
        "production_apply_enabled": False,
        "aws_credentials_requested": False,
        "aws_sts_verified": False,
        "github_approval_execution_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--commit", default="")
    parser.add_argument("--mode", choices=["dry-run"], default="dry-run")
    parser.add_argument("--xml", type=Path, default=ROOT / ".iac-reports/day25-security.xml")
    args = parser.parse_args()
    report = preflight(args.commit, args.mode) if args.preflight else static_evidence(args.xml)
    target = (
        ROOT
        / ".iac-reports"
        / ("day25-dry-run.json" if args.preflight else "day25-governance.json")
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Day25 governance: PASS; AWS credentials and production Apply remain disabled")


if __name__ == "__main__":
    main()
