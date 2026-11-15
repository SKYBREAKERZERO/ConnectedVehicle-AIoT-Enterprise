"""Day37 fail-closed AWS staging release admission and evidence gates.

No PR or audit-mode code obtains AWS credentials. This module never authorizes
production, grants approvals, creates AWS roles or writes cloud resources.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CalledProcessError
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from zipfile import BadZipFile

REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
RULESET_ID = 24828733
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REQUIRED_WORKFLOWS = {
    ".github/workflows/runtime.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/day35.yml",
    ".github/workflows/day36.yml",
}
PRODUCTION_FALSE = {"production_authorized": False, "release_authorized": False}
MAX_JSON = 5_000_000


def strict_load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ValueError("Missing, unsafe or oversized evidence file: " + str(path))

    def pairs(xs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in xs:
            if k in obj:
                raise ValueError("Duplicate JSON member")
            obj[k] = v
        return obj

    value = json.loads(
        path.read_bytes(),
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
    )
    if not isinstance(value, dict):
        raise ValueError("Evidence root must be object")
    return value


def dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")


def filehash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def api(path: str) -> Any:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ValueError("GitHub token missing")
    req = Request(
        "https://api.github.com/repos/" + REPO + "/" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(req, timeout=15) as result:
            return json.load(result)
    except HTTPError as error:
        raise ValueError(f"GitHub API refused evidence access: {error.code}") from None


def verify_ruleset(data: dict[str, Any]) -> None:
    if (
        data.get("target") != "branch"
        or data.get("enforcement") != "active"
        or data.get("conditions") != {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
    ):
        raise ValueError("Main ruleset does not enforce expected branch")
    # Missing visibility is not interpreted as an empty bypass list.
    if "bypass_actors" not in data or data["bypass_actors"] != []:
        raise ValueError("Main bypass actors not independently confirmed empty")
    rules = data.get("rules", [])
    reviews = [r.get("parameters", {}) for r in rules if r.get("type") == "pull_request"]
    checks = [r.get("parameters", {}) for r in rules if r.get("type") == "required_status_checks"]
    if (
        len(reviews) != 1
        or type(reviews[0].get("required_approving_review_count")) is not int
        or reviews[0]["required_approving_review_count"] < 1
    ):
        raise ValueError("Independent main approval missing")
    if not all(
        reviews[0].get(k) is True
        for k in (
            "dismiss_stale_reviews_on_push",
            "require_last_push_approval",
            "required_review_thread_resolution",
        )
    ):
        raise ValueError("Required review policy weakened")
    if len(checks) != 1 or checks[0].get("strict_required_status_checks_policy") is not True:
        raise ValueError("Main quality checks not strict")
    required = {
        (x.get("context"), x.get("integration_id"))
        for x in checks[0].get("required_status_checks", [])
    }
    core = {("Runtime quality gate", 15368), ("IaC quality gate", 15368)}
    day38_check = {("Day38 offline audit gate (not AWS release)", 15368)}
    if required not in (core, core | day38_check):
        raise ValueError("Main required status contexts changed")
    if not {"deletion", "non_fast_forward"}.issubset({r.get("type") for r in rules}):
        raise ValueError("Branch deletion/force push protection absent")


def choose_runs(rows: list[dict[str, Any]], commit: str) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = row.get("path", "").split("@")[0]
        if (
            path in REQUIRED_WORKFLOWS
            and row.get("head_sha") == commit
            and row.get("head_branch") == "main"
            and row.get("event") in {"push", "workflow_dispatch"}
        ):
            key = (
                row["created_at"],
                int(row.get("id", 0)),
                int(row.get("run_attempt", 0)),
            )
            old = selected.get(path)
            if old is None or key > (
                old["created_at"],
                int(old.get("id", 0)),
                int(old.get("run_attempt", 0)),
            ):
                selected[path] = row
    if set(selected) != REQUIRED_WORKFLOWS or any(
        r.get("status") != "completed" or r.get("conclusion") != "success"
        for r in selected.values()
    ):
        raise ValueError("Same protected-main SHA lacks latest successful Runtime/IaC/Day35/Day36")
    return selected


def day38_admission(rows: list[dict[str, Any]], commit: str) -> dict[str, Any]:
    """Require the latest protected-main Day38 run and its authentic same-attempt evidence.

    The observer workflow_run's green result never substitutes for the
    original Day38 push offline gate, and a PR cannot supply a main receipt.
    """
    from scripts import day38_readiness as d38
    from scripts import day39_trusted_verifier as d39

    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ValueError("Day38 protected-main evidence requires GitHub API token")
    security = d39.verify(commit, rows)
    offline = security["day38"]
    enterprise = offline.get("enterprise")
    if not (
        offline.get("decision") == "OFFLINE_AUDIT_PASS"
        and offline.get("candidate_sha") == commit
        and type(offline.get("run_id")) is int
        and offline["run_id"] > 0
        and type(offline.get("run_attempt")) is int
        and offline["run_attempt"] > 0
        and isinstance(offline.get("audit_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", offline["audit_sha256"]) is not None
        and isinstance(enterprise, dict)
        and enterprise.get("final_gate") == "OFFLINE_AUDIT_PASS"
        and enterprise.get("stage_count") == len(d38.DAY38_REQUIRED_STAGES)
        and enterprise.get("probe_count") == 12
        and isinstance(enterprise.get("probe_index_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", enterprise["probe_index_sha256"]) is not None
        and isinstance(enterprise.get("aggregate_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", enterprise["aggregate_sha256"]) is not None
    ):
        raise ValueError("Latest Day38 protected-main offline evidence is incomplete")
    return {
        "candidate_sha": commit,
        "run_id": offline["run_id"],
        "run_attempt": offline["run_attempt"],
        "audit_sha256": offline["audit_sha256"],
        "aggregate_sha256": enterprise["aggregate_sha256"],
        "stage_count": enterprise["stage_count"],
        "probe_count": enterprise["probe_count"],
        "probe_index_sha256": enterprise["probe_index_sha256"],
        "decision": "OFFLINE_AUDIT_PASS",
        "security": security,
    }


def admission(commit: str) -> dict[str, Any]:
    from scripts import day39_trusted_verifier as d39

    if (
        not SHA.fullmatch(commit)
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_REPOSITORY") != REPO
        or os.environ.get("GITHUB_SHA") != commit
    ):
        raise ValueError("Only exact dispatched protected-main commit is admissible")
    branch = api("branches/main")
    if branch.get("commit", {}).get("sha") != commit:
        raise ValueError("The release commit is not the current main HEAD")
    verify_ruleset(api(f"rulesets/{RULESET_ID}"))
    results = api(f"actions/runs?head_sha={commit}&per_page=100")
    rows = results.get("workflow_runs", [])
    if results.get("total_count") != len(rows) or len(rows) > 100:
        raise ValueError("Ambiguous upstream workflow pagination")
    latest = choose_runs(rows, commit)
    day38 = day38_admission(rows, commit)
    runtime_security = d39.verify_runtime(commit, latest[d39.RUNTIME_PATH])
    day36 = latest[".github/workflows/day36.yml"]
    started = datetime.fromisoformat(day36.get("run_started_at", "").replace("Z", "+00:00"))
    if not 0 <= (datetime.now(UTC) - started).total_seconds() <= 5400:
        raise ValueError("Day36 vulnerability/Staging evidence requires fresh same-SHA rerun")
    names = {
        x.get("name")
        for x in api(f"actions/runs/{day36['id']}/artifacts?per_page=100").get("artifacts", [])
        if not x.get("expired")
    }
    attempt = day36.get("run_attempt")
    for expected in (
        f"day36-images-{day36['id']}-{attempt}",
        f"day36-staging-{day36['id']}-{attempt}",
        f"day36-final-{day36['id']}-{attempt}",
    ):
        if expected not in names:
            raise ValueError("Day36 same-attempt required proof expired or missing: " + expected)
    fresh = api(f"actions/runs?head_sha={commit}&per_page=100")
    fresh_rows = fresh.get("workflow_runs", [])
    if (
        fresh.get("total_count") != len(fresh_rows)
        or len(fresh_rows) > 100
        or {k: d39.run_identity(r) for k, r in choose_runs(fresh_rows, commit).items()}
        != {k: d39.run_identity(r) for k, r in latest.items()}
    ):
        raise ValueError("Upstream workflow changed during release admission")
    fresh_security = d39.newest(fresh_rows, commit)
    if (fresh_security["id"], fresh_security["run_attempt"]) != (
        day38["run_id"],
        day38["run_attempt"],
    ):
        raise ValueError("Day38 security attempt changed during release admission")
    if api("branches/main").get("commit", {}).get("sha") != commit:
        raise ValueError("The release commit is no longer the current main HEAD")
    return {
        "decision": "TRUSTED_MAIN_SOURCE_ADMITTED",
        "commit": commit,
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "day36_run_id": str(day36["id"]),
        "day36_attempt": str(attempt),
        "upstream": {
            k: {"id": r["id"], "attempt": r["run_attempt"], "sha": r["head_sha"]}
            for k, r in latest.items()
        },
        "day38": day38,
        "runtime_security": runtime_security,
        "governance": "main-ruleset-24828733-verified",
        **PRODUCTION_FALSE,
    }


def plan_check(
    plan: dict[str, Any], *, expected_digest: str | None = None, phase: str | None = None
) -> dict[str, Any]:
    """Fail closed on all delete/replace and unreviewed IAM/SG changes.

    The bootstrap allowlist is intentionally create-only; ECS deploy may only
    create/update its exact task definition and service. Read-only audit uses
    Terraform -refresh-only and must contain no infrastructure changes.
    """
    phase = phase or ("deploy" if expected_digest is not None else "bootstrap")
    if phase not in {"audit", "bootstrap", "deploy"}:
        raise ValueError("Unrecognized Plan phase")
    if phase == "audit" and plan.get("resource_drift"):
        raise ValueError("Audit detected drift; remediation requires separate approved Plan")
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        raise ValueError("Invalid Terraform plan")
    bootstrap_types = {
        "aws_ecr_repository",
        "aws_ecs_cluster",
        "aws_cloudwatch_log_group",
        "aws_security_group",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
    }
    deploy_types = {"aws_ecs_task_definition", "aws_ecs_service"}
    for change in changes:
        actions = change.get("change", {}).get("actions", [])
        addr, resource_type = change.get("address", ""), change.get("type", "")
        if (
            not isinstance(actions, list)
            or not actions
            or any(action not in {"create", "read", "update", "no-op"} for action in actions)
            or "delete" in actions
            or not isinstance(addr, str)
            or addr.startswith("module.production")
            or change.get("mode", "managed") not in {"managed", "data"}
        ):
            raise ValueError("Destructive, foreign or unknown Terraform action: " + str(addr))
        if all(a in {"read", "no-op"} for a in actions):
            continue
        if phase == "audit":
            raise ValueError("Audit/refresh-only Plan must not mutate infrastructure")
        if phase == "bootstrap":
            if resource_type not in bootstrap_types or actions != ["create"]:
                raise ValueError(
                    "Bootstrap refuses updates/replacements or non-foundation resource: " + addr
                )
        else:
            if resource_type not in deploy_types or actions not in (["create"], ["update"]):
                raise ValueError("Deploy refuses IAM, network, ECR or unrelated change: " + addr)
    variables = plan.get("variables", {})
    service = variables.get("enable_service", {}).get("value")
    if phase != "deploy":
        if service is not False:
            raise ValueError("Infrastructure or audit mode requires disabled service")
    else:
        if (
            not expected_digest
            or not DIGEST.fullmatch(expected_digest)
            or service is not True
            or variables.get("image_digest", {}).get("value") != expected_digest
        ):
            raise ValueError("ECS deploy does not match exact approved ECR Manifest Digest")
        tasks = [r for r in changes if r.get("type") == "aws_ecs_task_definition"]
        tasks += [
            r
            for r in plan.get("planned_values", {}).get("root_module", {}).get("resources", [])
            if r.get("type") == "aws_ecs_task_definition"
        ]
        if not tasks:
            raise ValueError("ECS Task Definition missing from deployment plan")
        for task in tasks:
            values = task.get("change", {}).get("after", task.get("values", {})) or {}
            raw = values.get("container_definitions")
            if raw is None:
                raise ValueError("Unknown ECS image in plan")
            containers = json.loads(raw)
            if (
                len(containers) != 1
                or containers[0].get("name", "vehicle-api") != "vehicle-api"
                or not containers[0].get("image", "").endswith("@" + expected_digest)
            ):
                raise ValueError("Unexpected or mutable ECS image in Plan")
    return {
        "decision": "NON_DESTRUCTIVE_TERRAFORM_PLAN",
        "phase": phase,
        "service_enabled": bool(service),
        "resource_changes": len(changes),
        "image_digest": expected_digest,
        **PRODUCTION_FALSE,
    }


def final(
    mode: str, needs: dict[str, Any], folder: Path, commit: str, run: str, attempt: str
) -> dict[str, Any]:
    expected = {
        "source",
        "admission",
        "plan",
        "bootstrap",
        "publish",
        "deploy_plan",
        "deploy",
        "verify",
        "close",
        "recovery",
    }
    if set(needs) != expected or mode not in {"audit", "plan", "bootstrap", "deploy"}:
        raise ValueError("Unexpected DAG or mode")
    statuses = {k: v.get("result") for k, v in needs.items()}
    required = {
        "audit": {"source"},
        "plan": {"source", "admission", "plan"},
        "bootstrap": {"source", "admission", "plan", "bootstrap"},
        "deploy": {"source", "admission", "publish", "deploy_plan", "deploy", "verify", "close"},
    }[mode]
    if any(statuses[k] != ("success" if k in required else "skipped") for k in expected):
        raise ValueError("Missing, failed, cancelled or unexpected job status")
    output: dict[str, Any] = {
        "decision": {
            "audit": "READY_FOR_CONFIGURATION_REVIEW",
            "plan": "READY_FOR_STAGING_PLAN_REVIEW",
            "bootstrap": "AWS_STAGING_INFRA_BOOTSTRAPPED",
            "deploy": "AWS_STAGING_SERVICE_VERIFIED",
        }[mode],
        "commit": commit,
        "run_id": run,
        "run_attempt": attempt,
        "mode": mode,
        **PRODUCTION_FALSE,
        "real_aws_verified": mode == "deploy",
        "physical_ecu_verified": False,
        "proofs": {},
    }
    if mode != "audit":
        a = strict_load(folder / "admission/admission.json")
        if (
            any(
                str(a.get(k)) != str(v)
                for k, v in (("commit", commit), ("run_id", run), ("run_attempt", attempt))
            )
            or a.get("release_authorized") is not False
        ):
            raise ValueError("Source admission provenance mismatch")
        security = a.get("day38", {}).get("security", {})
        runtime = a.get("runtime_security", {})
        if (
            security.get("decision") != "DAY39_SECURITY_PASS"
            or security.get("verifier_sha") != commit
            or security.get("candidate_sha") != commit
            or security.get("aws_authorized") is not False
            or security.get("production_authorized") is not False
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime.get("digest", ""))) is None
        ):
            raise ValueError("Missing or mismatched Day39 security admission")
        output["proofs"]["admission.json"] = filehash(folder / "admission/admission.json")
    if mode == "plan":
        p = strict_load(folder / "plan/plan-summary.json")
        if (
            p.get("decision") != "NON_DESTRUCTIVE_TERRAFORM_PLAN"
            or p.get("service_enabled") is not False
            or p.get("phase") != "audit"
        ):
            raise ValueError("Plan-only evidence invalid")
        output["proofs"]["plan-summary.json"] = filehash(folder / "plan/plan-summary.json")
    if mode == "bootstrap":
        p = strict_load(folder / "plan/plan-summary.json")
        receipt = strict_load(folder / "plan/receipt.json")
        if (
            p.get("decision") != "NON_DESTRUCTIVE_TERRAFORM_PLAN"
            or p.get("phase") != "bootstrap"
            or receipt.get("phase") != "bootstrap"
            or receipt.get("decision") != "PRIVATE_VERSIONED_PLAN_STORED"
            or receipt.get("commit") != commit
            or str(receipt.get("run_id")) != run
            or str(receipt.get("run_attempt")) != attempt
        ):
            raise ValueError("Bootstrap exact Plan approval receipt invalid")
        output["proofs"]["bootstrap-plan.json"] = filehash(folder / "plan/receipt.json")
        b = strict_load(folder / "bootstrap/bootstrap.json")
        if (
            b.get("decision") != "STAGING_INFRA_BOOTSTRAPPED"
            or b.get("commit") != commit
            or str(b.get("run_id")) != run
            or str(b.get("run_attempt")) != attempt
            or b.get("release_authorized") is not False
        ):
            raise ValueError("Infrastructure bootstrap evidence invalid")
        output["proofs"]["bootstrap.json"] = filehash(folder / "bootstrap/bootstrap.json")
    if mode == "deploy":
        plan_public = strict_load(folder / "deploy-plan/plan-summary.json")
        plan_receipt = strict_load(folder / "deploy-plan/receipt.json")
        if (
            plan_public.get("phase") != "deploy"
            or plan_public.get("decision") != "NON_DESTRUCTIVE_TERRAFORM_PLAN"
            or plan_receipt.get("phase") != "deploy"
            or plan_receipt.get("decision") != "PRIVATE_VERSIONED_PLAN_STORED"
            or plan_receipt.get("commit") != commit
            or str(plan_receipt.get("run_id")) != run
            or str(plan_receipt.get("run_attempt")) != attempt
        ):
            raise ValueError("Deploy saved Plan receipt missing or foreign")
        r = strict_load(folder / "publish/release.json")
        v = strict_load(folder / "verify/verified.json")
        d = strict_load(folder / "deploy/deployment.json")
        close = strict_load(folder / "close/closed.json")
        for evidence in (r, v, d):
            if (
                evidence.get("commit") != commit
                or str(evidence.get("run_id")) != run
                or str(evidence.get("run_attempt")) != attempt
            ):
                raise ValueError("Cross-job source/Run/Attempt mismatch")
        if str(r.get("day36_run_id")) != str(a.get("day36_run_id")) or str(
            r.get("day36_attempt")
        ) != str(a.get("day36_attempt")):
            raise ValueError("Release references different Day36 Run/Attempt")
        if (
            not DIGEST.fullmatch(r.get("registry_digest", ""))
            or r["image_uri"] != v.get("image_uri")
            or r["image_uri"] != d.get("image_uri")
            or r["registry_digest"] != d.get("registry_digest")
            or v.get("decision") != "ECS_TASK_DIGEST_HEALTH_VERIFIED"
            or not isinstance(v.get("tasks"), list)
            or len(v["tasks"]) != v.get("desired_count")
            or not all(t.get("image_digest") == r["registry_digest"] for t in v["tasks"])
            or plan_receipt.get("image_digest") != r["registry_digest"]
            or close.get("decision") != "STAGING_TERRAFORM_ZERO_DRIFT_AND_FENCE_CLOSED"
            or close.get("commit") != commit
            or str(close.get("run_id")) != run
            or str(close.get("run_attempt")) != attempt
            or close.get("registry_digest") != r["registry_digest"]
        ):
            raise ValueError("ECR/ECS registry digest or health proof mismatch")
        for k, name in (
            ("publish/release.json", "release.json"),
            ("deploy/deployment.json", "deployment.json"),
            ("verify/verified.json", "verified.json"),
            ("deploy-plan/receipt.json", "deploy-plan-receipt.json"),
            ("close/closed.json", "closure.json"),
        ):
            output["proofs"][name] = filehash(folder / k)
        output.update(
            image_uri=r["image_uri"],
            registry_digest=r["registry_digest"],
            aws_account_id=v["aws_account_id"],
        )
    return output


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("admission", "plan-check", "final"))
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--input", type=Path)
    p.add_argument("--digest")
    p.add_argument("--phase", choices=("audit", "bootstrap", "deploy"))
    p.add_argument("--mode", default="audit")
    p.add_argument("--folder", type=Path, default=Path(".day37/check"))
    a = p.parse_args()
    try:
        if a.command == "admission":
            result = admission(a.commit)
        elif a.command == "plan-check":
            if a.input is None:
                raise ValueError("Terraform JSON plan required")
            result = plan_check(strict_load(a.input), expected_digest=a.digest, phase=a.phase)
        else:
            needs = json.loads(os.environ.get("PIPELINE_NEEDS", "{}"))
            result = final(
                a.mode,
                needs,
                a.folder,
                a.commit,
                os.environ.get("GITHUB_RUN_ID", "local"),
                os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            )
    except (ValueError, KeyError, OSError, TypeError, BadZipFile, CalledProcessError) as error:
        result = {
            "decision": "BLOCKED",
            "reason": str(error),
            "mode": a.mode,
            "commit": a.commit,
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            **PRODUCTION_FALSE,
        }
        dump(a.output, result)
        raise SystemExit(1) from None
    dump(a.output, result)


if __name__ == "__main__":
    main()
