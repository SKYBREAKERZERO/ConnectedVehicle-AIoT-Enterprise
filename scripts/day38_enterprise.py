"""Day38 hardened offline stage proofs, negative probes and evidence aggregation.

This module is safe for untrusted PR CI: no AWS SDK, credentials, terraform apply,
state writes, or cloud privilege. A stage report is never deployment approval.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
import re
import stat
import sys
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts import day38_readiness as verifier

REPO = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
ROOTS = ("ota-staging", "ota-staging-foundation", "ota-staging-identity")
GROUPS = ("foundation", "ota", "governance", "roots")
MANDATORY_STAGES = (
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
PROBE_CASES = (
    "duplicate-json",
    "nonfinite-json",
    "zip-traversal",
    "zip-symlink",
    "zip-duplicate",
    "zip-oversize",
    "manifest-tamper",
    "attempt-replay",
    "ruleset-bypass",
    "fault-oracle",
    "fault-consumer",
    "future-run-failure",
)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
STAGE = re.compile(r"day38-[a-z0-9-]+\Z")
MAX_JSON = 2_000_000


def require(ok: Any, msg: str) -> None:
    if not ok:
        raise ValueError("DAY38 BLOCKED: " + msg)


def raw_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict[str, Any]:
    require(not path.is_symlink() and path.is_file(), "missing or linked JSON: " + str(path))
    require(path.stat().st_size <= MAX_JSON, "oversized JSON evidence")
    return verifier.strict_json(path.read_bytes())


def write(path: Path, payload: dict[str, Any]) -> None:
    require(not path.exists() and not path.is_symlink(), "output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )


def current_identity() -> dict[str, Any]:
    head = os.environ.get("GITHUB_SHA", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    require(repo == REPO and SHA40.fullmatch(head), "repository or candidate SHA mismatch")
    require(run.isdigit() and int(run) > 0, "invalid GitHub run ID")
    require(attempt.isdigit() and int(attempt) > 0, "invalid GitHub run attempt")
    return {
        "repository": repo,
        "candidate_sha": head,
        "run_id": int(run),
        "run_attempt": int(attempt),
    }


def source_guard() -> dict[str, Any]:
    i = current_identity()
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    ref = os.environ.get("GITHUB_REF", "")
    require(
        event in {"pull_request", "push", "merge_group", "workflow_dispatch"},
        "unexpected source event",
    )
    if event in {"push", "workflow_dispatch"}:
        require(ref == "refs/heads/main", "branch is not main")
    elif event == "pull_request":
        require(re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref), "PR merge ref required")
    elif event == "merge_group":
        require(ref.startswith("refs/heads/gh-readonly-queue/main/"), "wrong merge queue")
    i["event"] = event
    i["ref"] = ref
    i["release_authorized"] = False
    return i


def inspect_root(root: str) -> dict[str, Any]:
    require(root in ROOTS, "unreviewed AWS Terraform root")
    path = Path("infra/terraform/environments") / root
    require(path.is_dir() and not path.is_symlink(), "missing reviewed root")
    tf = sorted(path.glob("*.tf"))
    require(bool(tf), "AWS root missing Terraform source")
    require(all(x.is_file() and not x.is_symlink() for x in tf), "linked Terraform source")
    lock = path / ".terraform.lock.hcl"
    require(lock.is_file() and not lock.is_symlink(), "provider lock file missing")
    require(all(x.stat().st_size <= 1_000_000 for x in tf), "oversized HCL source")
    require(not list(path.glob("*.tf.json")), "unreviewed Terraform JSON source")
    return {
        "root": root,
        "tf_files": [str(x) for x in tf],
        "provider_lock_sha256": raw_sha(lock.read_bytes()),
        "backend_initialized": False,
        "release_authorized": False,
    }


def verify_workflow_contract(path: Path) -> dict[str, Any]:
    yaml = importlib.import_module("yaml")  # Pinned, runtime-installed IaC dependency.

    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(
        isinstance(cfg, dict) and cfg.get("name") == verifier.DAY38_NAME,
        "unexpected workflow identity",
    )
    on = cfg.get("on", cfg.get(True))
    require(isinstance(on, dict), "workflow event declaration missing")
    require(
        set(on)
        == {"pull_request", "push", "merge_group", "workflow_dispatch", "schedule", "workflow_run"},
        "unexpected workflow trigger",
    )
    require(
        on["schedule"] == [{"cron": "17 * * * *"}],
        "reviewed default-branch recheck schedule is missing or changed",
    )
    require(
        cfg.get("permissions") == {"contents": "read", "actions": "read", "pull-requests": "read"},
        "workflow must have only read-only permissions",
    )
    concurrency = cfg.get("concurrency", {})
    require(concurrency.get("cancel-in-progress") is False, "unsafe workflow cancellation")
    group = str(concurrency.get("group", ""))
    require(
        "github.run_id" in group and "github.run_attempt" in group,
        "run and attempt must not share a cancellable group",
    )
    jobs = cfg.get("jobs")
    require(isinstance(jobs, dict), "workflow missing jobs")
    for name in ("offline", "readiness", "offline_gate", "readiness_gate", "evidence"):
        require(name in jobs, "mandatory Day38 gate missing: " + name)
    for _, job in jobs.items():
        require(isinstance(job, dict), "invalid job")
        permissions = job.get("permissions", {})
        require(
            isinstance(permissions, dict)
            and all(value == "read" for value in permissions.values()),
            "write permissions forbidden in PR-editable workflow",
        )
        require(
            "id-token" not in permissions and "deployments" not in permissions,
            "AWS or deployment permissions forbidden",
        )
        require(job.get("environment") is None, "unreviewed environment in read-only workflow")
        for step in job.get("steps", []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            require(
                not uses.startswith("aws-actions/configure-aws-credentials"),
                "AWS credentials denied",
            )
            run = step.get("run", "")
            require(
                "actions/workflows/day38-release-readiness.yml/dispatches" not in run,
                "self-dispatch requires untrusted write permissions",
            )
            # Conservative denylist for shell commands; Python modules are also unit tested.
            require(
                not re.search(
                    r"\bterraform\s+(?:apply|destroy|import|state\s+(?:rm|mv|push))\b", run
                ),
                "Terraform mutation denied",
            )
            require(
                not re.search(r"\baws\s+(?:cloudformation|ecs|iam|s3api)\b", run),
                "direct AWS operations forbidden",
            )
    required = jobs["offline_gate"].get("needs", [])
    require(
        "evidence" in required and "offline" in required,
        "final offline gate must independently consume evidence",
    )
    require(
        jobs["readiness"].get("if") is not None, "trusted evidence observation must be event-bound"
    )
    return {
        "workflow": cfg["name"],
        "job_count": len(jobs),
        "event_count": len(on),
        "aws_authority": False,
    }


def denial(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except (ValueError, TypeError, zipfile.BadZipFile):
        return
    raise AssertionError("negative probe failed: malformed evidence was accepted")


def zipped(contents: list[tuple[str, bytes]], *, symlink: bool = False) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in contents:
            info = zipfile.ZipInfo(name)
            if symlink:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, data)
    return out.getvalue()


def probe(name: str) -> None:
    require(name in PROBE_CASES, "unrecognized negative probe")
    r = verifier
    if name == "duplicate-json":
        denial(lambda: r.strict_json(b'{"x":1,"x":2}'))
    elif name == "nonfinite-json":
        denial(lambda: r.strict_json(b'{"x":NaN}'))
    elif name == "zip-traversal":
        denial(lambda: r.check_zip(zipped([("../escape.json", b"{}")])))
    elif name == "zip-symlink":
        denial(lambda: r.check_zip(zipped([("secret.json", b"{}")], symlink=True)))
    elif name == "zip-duplicate":
        denial(lambda: r.check_zip(zipped([("a.json", b"{}"), ("a.json", b"{}")])))
    elif name == "zip-oversize":
        denial(lambda: r.check_zip(zipped([("a.json", b"0" * (r.MAX_MEMBER + 1))])))
    elif name in {"manifest-tamper", "attempt-replay"}:
        manifest = {
            "version": 1,
            "stage": "iac-policy",
            "provenance": {
                "day31_commit": "a" * 40,
                "day31_run_id": "12:1",
                "day31_source_sha256": "b" * 64,
            },
            "files": {"report.json": r.digest(b"{}")},
        }
        members = {"manifest.json": json.dumps(manifest).encode(), "report.json": b"{}"}
        if name == "manifest-tamper":
            members["report.json"] = b'{"tampered":true}'
            denial(lambda: r.verify_sealed(members, "iac-policy", {"id": 12, "run_attempt": 1}))
        else:
            denial(lambda: r.verify_sealed(members, "iac-policy", {"id": 12, "run_attempt": 2}))
    elif name == "ruleset-bypass":
        denial(
            lambda: r.verify_main_ruleset(
                {
                    "target": "branch",
                    "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                    "bypass_actors": [{"actor_id": 1, "actor_type": "Team"}],
                    "rules": [],
                }
            )
        )
    elif name == "fault-oracle":
        denial(
            lambda: r.verify_fault_job_matrix(
                [
                    {
                        "name": "fault (iac, failure) / oracle",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            )
        )
    elif name == "fault-consumer":
        denial(
            lambda: r.verify_fault_receipt(
                {"graph": "iac", "scenario": "tamper", "fault_blocked": False},
                {"id": 10, "run_attempt": 1},
                "iac",
                "tamper",
                "a" * 40,
            )
        )
    elif name == "future-run-failure":
        path = next(iter(r.WORKFLOWS))
        rows = [
            {
                "path": path,
                "name": r.WORKFLOWS[path],
                "head_sha": "a" * 40,
                "event": "pull_request",
                "head_branch": "feature",
                "id": 11,
                "run_attempt": 1,
                "run_started_at": "2026-11-08T00:00:00Z",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "path": path,
                "name": r.WORKFLOWS[path],
                "head_sha": "a" * 40,
                "event": "pull_request",
                "head_branch": "feature",
                "id": 12,
                "run_attempt": 1,
                "run_started_at": "2026-11-08T01:00:00Z",
                "status": "completed",
                "conclusion": "failure",
            },
        ]
        denial(lambda: r.selected_runs(rows, "a" * 40, "pull_request", "feature"))


def stage_report(stage: str, proof: Path, dest: Path) -> None:
    require(
        STAGE.fullmatch(stage) is not None and stage in MANDATORY_STAGES, "unsupported report stage"
    )
    identity = current_identity()
    require(
        proof.is_file() and not proof.is_symlink() and proof.stat().st_size <= 6_000_000,
        "missing or oversized stage proof",
    )
    raw = proof.read_bytes()
    require(bool(raw), "empty stage proof")
    report = {
        "schema_version": "day38.stage.v1",
        "stage": stage,
        "decision": "VERIFIED_BY_RUNNER",
        "source": identity,
        "proof_name": proof.name,
        "proof_sha256": raw_sha(raw),
        "proof_bytes": len(raw),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "release_authorized": False,
        "aws_mutation_allowed": False,
    }
    write(dest, report)


def stage_lookup(folder: Path, expected: str) -> tuple[dict[str, Any], dict[str, Any]]:
    require(
        (folder / "manifest.json").is_file() and not (folder / "manifest.json").is_symlink(),
        "missing sealed stage manifest",
    )
    from scripts.iac.pipeline_evidence import verify

    require(folder.is_dir() and not folder.is_symlink(), "missing stage bundle")
    hashes = verify(folder, expected)
    require(len(hashes) == 1, "stage must contain exactly one report")
    report_name = next(iter(hashes))
    report = load(folder / report_name)
    require(
        report.get("schema_version") == "day38.stage.v1"
        and report.get("stage") == expected
        and report.get("decision") == "VERIFIED_BY_RUNNER"
        and report.get("source") == current_identity()
        and report.get("release_authorized") is False
        and report.get("aws_mutation_allowed") is False
        and SHA64.fullmatch(str(report.get("proof_sha256", "")))
        and type(report.get("proof_bytes")) is int
        and report["proof_bytes"] > 0,
        "invalid stage receipt or source identity",
    )
    return report, {
        "manifest_sha256": raw_sha((folder / "manifest.json").read_bytes()),
        "report_sha256": hashes[report_name],
        "source": report["source"],
    }


def aggregate(folder: Path, dest: Path) -> None:
    require(folder.is_dir() and not folder.is_symlink(), "missing stage input root")
    roots = {p.name for p in folder.iterdir()}
    require(roots == set(MANDATORY_STAGES), "missing, unknown or duplicated stage bundles")
    stages: dict[str, Any] = {}
    for stage in MANDATORY_STAGES:
        _, summary = stage_lookup(folder / stage, stage)
        stages[stage] = summary
    output = {
        "schema_version": "day38.aggregate.v1",
        "decision": "OFFLINE_STAGE_EVIDENCE_VERIFIED",
        "source": current_identity(),
        "mandatory_stages": list(MANDATORY_STAGES),
        "stages": stages,
        "release_authorized": False,
        "aws_plan_or_apply_executed": False,
    }
    write(dest, output)


def verify_aggregate(path: Path) -> None:
    obj = load(path)
    require(
        obj.get("schema_version") == "day38.aggregate.v1"
        and obj.get("decision") == "OFFLINE_STAGE_EVIDENCE_VERIFIED"
        and obj.get("source") == current_identity()
        and obj.get("mandatory_stages") == list(MANDATORY_STAGES)
        and isinstance(obj.get("stages"), dict)
        and set(obj["stages"]) == set(MANDATORY_STAGES)
        and obj.get("release_authorized") is False
        and obj.get("aws_plan_or_apply_executed") is False,
        "invalid aggregate evidence or deployment authority",
    )
    for value in obj["stages"].values():
        require(
            value.get("source") == current_identity()
            and SHA64.fullmatch(str(value.get("manifest_sha256", "")))
            and SHA64.fullmatch(str(value.get("report_sha256", ""))),
            "aggregate stage provenance mismatch",
        )


def needs_check(needs: dict[str, Any], keys: set[str]) -> None:
    require(set(needs) == keys, "unexpected gate dependencies")
    require(
        all(isinstance(v, dict) and v.get("result") == "success" for v in needs.values()),
        "mandatory job failure, cancellation or skip",
    )


def final_gate(needs_json: str, aggregate_path: Path, dest: Path) -> int:
    expected_jobs = {
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
    try:
        needs = verifier.strict_json(needs_json.encode())
        needs_check(needs, expected_jobs)
        verify_aggregate(aggregate_path)
        result = {
            "schema_version": "day38.gate.v1",
            "decision": "OFFLINE_AUDIT_PASS",
            "source": current_identity(),
            "aggregate_sha256": raw_sha(aggregate_path.read_bytes()),
            "aws_authorized": False,
            "release_authorized": False,
        }
    except (ValueError, TypeError, OSError, KeyError) as exc:
        result = {
            "schema_version": "day38.gate.v1",
            "decision": "BLOCKED",
            "reason_code": type(exc).__name__,
            "source": current_identity(),
            "aws_authorized": False,
            "release_authorized": False,
        }
    write(dest, result)
    print(f"Day38 final offline gate: {result['decision']}")
    return 0 if result["decision"] == "OFFLINE_AUDIT_PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("source")
    p = sub.add_parser("root")
    p.add_argument("--name", required=True)
    p = sub.add_parser("workflow")
    p.add_argument("--path", type=Path, required=True)
    p = sub.add_parser("probe")
    p.add_argument("--scenario", required=True)
    p = sub.add_parser("report")
    p.add_argument("--stage", required=True)
    p.add_argument("--proof", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("aggregate")
    p.add_argument("--folder", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("verify-aggregate")
    p.add_argument("--input", type=Path, required=True)
    p = sub.add_parser("gate")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "source":
        print(json.dumps(source_guard(), sort_keys=True))
    elif args.command == "root":
        print(json.dumps(inspect_root(args.name), sort_keys=True))
    elif args.command == "workflow":
        print(json.dumps(verify_workflow_contract(args.path), sort_keys=True))
    elif args.command == "probe":
        probe(args.scenario)
        print("P0 negative scenario DENIED: " + args.scenario)
    elif args.command == "report":
        stage_report(args.stage, args.proof, args.output)
    elif args.command == "aggregate":
        aggregate(args.folder, args.output)
    elif args.command == "verify-aggregate":
        verify_aggregate(args.input)
    elif args.command == "gate":
        return final_gate(os.environ.get("DAY38_NEEDS", "{}"), args.input, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
