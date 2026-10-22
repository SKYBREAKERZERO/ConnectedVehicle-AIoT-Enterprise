"""Review a saved governance retirement plan; never apply or change Terraform state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PHASES = {
    "detach": ("aws_organizations_policy_attachment", ("id", "policy_id", "target_id")),
    "delete-policy": ("aws_organizations_policy", ("id",)),
    "delete-empty-ous": ("aws_organizations_organizational_unit", ("id", "parent_id")),
    "finish-local-guard": ("terraform_data", ("id",)),
}


def review(plan: dict[str, Any], manifest: dict[str, Any], commit: str) -> dict[str, Any]:
    """Allow only exact, independently reviewed deletions in one retirement phase."""
    required = {"version", "operation_id", "actor", "reason", "source_commit", "phase", "resources"}
    if (
        set(manifest) != required
        or type(manifest["version"]) is not int
        or manifest["version"] != 1
    ):
        raise ValueError("Invalid retirement manifest schema")
    if re.fullmatch(r"[0-9a-f]{32}", str(manifest["operation_id"])) is None:
        raise ValueError("Invalid retirement operation ID")
    if any(
        not isinstance(manifest[k], str) or not manifest[k].strip() for k in ("actor", "reason")
    ):
        raise ValueError("Retirement actor and reason are required")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None or manifest["source_commit"] != commit:
        raise ValueError("Manifest must match the current reviewed source commit")
    if manifest["phase"] not in PHASES:
        raise ValueError("Unsupported retirement phase")
    kind, fields = PHASES[manifest["phase"]]
    if not isinstance(manifest["resources"], list) or not manifest["resources"]:
        raise ValueError("An exact nonempty resource allowlist is required")
    expected = {}
    for entry in manifest["resources"]:
        if not isinstance(entry, dict) or set(entry) != {"address", *fields}:
            raise ValueError("Invalid retirement resource identity")
        address = entry["address"]
        if not isinstance(address, str) or not address.startswith(f"module.governance.{kind}."):
            raise ValueError("Retirement may only target the governance module")
        if address in expected or any(
            not isinstance(entry[f], str) or not entry[f] for f in fields
        ):
            raise ValueError("Duplicate or missing retirement identity")
        expected[address] = entry
    if (
        plan.get("errored")
        or plan.get("complete") is not True
        or plan.get("deferred_changes")
        or not str(plan.get("format_version", "")).startswith("1.")
        or not isinstance(plan.get("planned_values"), dict)
        or not isinstance(plan.get("resource_changes"), list)
    ):
        raise ValueError("Incomplete or invalid saved plan")
    found: set[str] = set()
    for resource in plan["resource_changes"]:
        change = resource["change"]
        actions = change["actions"]
        if actions in (["no-op"], ["read"]):
            continue
        address = resource["address"]
        if (
            resource.get("mode", "managed") != "managed"
            or resource.get("type") != kind
            or actions != ["delete"]
            or address not in expected
            or address in found
            or change.get("after") is not None
            or change.get("after_unknown")
            or any(change.get("before", {}).get(f) != expected[address][f] for f in fields)
        ):
            raise ValueError("Plan exceeds the exact retirement deletion allowlist")
        found.add(address)
    if found != set(expected):
        raise ValueError("Plan does not contain every approved retirement deletion")
    return {
        "status": "reviewed-not-applied",
        "operation_id": manifest["operation_id"],
        "actor": manifest["actor"],
        "reason": manifest["reason"],
        "source_commit": commit,
        "phase": manifest["phase"],
        "addresses": sorted(found),
    }


def publish(path: Path, report: dict[str, Any]) -> None:
    """Publish complete evidence without overwriting another operation's report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as f:
            temporary = Path(f.name)
            json.dump(report, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.resolve() in {
            args.plan.resolve(),
            args.manifest.resolve(),
        }:
            raise ValueError("Evidence must use a new destination, separate from the input files")
        repo = Path(__file__).resolve().parents[2]
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, encoding="utf-8", timeout=30
        ).strip()
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, timeout=30):
            raise ValueError("Commit the reviewed maintenance source; the worktree must be clean")
        shown = subprocess.check_output(
            [
                "terraform",
                f"-chdir={args.root.resolve()}",
                "show",
                "-json",
                str(args.plan.resolve()),
            ],
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        report = review(
            json.loads(shown), json.loads(args.manifest.read_text(encoding="utf-8")), commit
        )
        report.update(
            plan_sha256=hashlib.sha256(args.plan.read_bytes()).hexdigest(),
            manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            reviewed_at_utc=datetime.now(UTC).isoformat(),
        )
        publish(args.output, report)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"Retirement review rejected: {type(exc).__name__}\n")
    print("Retirement plan reviewed; no apply or state mutation was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
