"""Explicit, exhaustive Terraform contract partitions and verified report reduction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

GROUPS: dict[str, tuple[str, ...]] = {
    "foundation": (
        "modules/messaging",
        "modules/security/iam-policy",
        "modules/security/iam-role",
        "modules/security/kms-key",
        "modules/security/secret",
    ),
    "ota": (
        "modules/ota-artifact-bucket",
        "modules/ota-artifact-policy",
        "modules/ota-governance",
        "modules/ota-runtime-iam",
        "modules/ota-secrets",
    ),
    "governance": (
        "bootstrap/state-backend",
        "modules/github-oidc-deploy",
        "modules/terraform-state-store",
    ),
    "roots": (
        "environments/dev",
        "environments/governance-local",
        "environments/local",
        "environments/ota-local",
    ),
}


def partition(roots: list[Path], candidate: Path, group: str) -> list[Path]:
    if group != "all" and group not in GROUPS:
        raise ValueError("unknown contract group")
    actual = [p.relative_to(candidate).as_posix() for p in roots]
    expected = [name for names in GROUPS.values() for name in names]
    configured = {
        p.parent.relative_to(candidate).as_posix()
        for base in ("modules", "bootstrap", "environments")
        for p in (candidate / base).rglob("*.tf")
        if ".terraform" not in p.parts
    }
    if (
        len(set(expected)) != len(expected)
        or len(set(actual)) != len(actual)
        or set(actual) != set(expected)
        or configured != set(expected)
    ):
        raise ValueError("Terraform root inventory changed; review the exhaustive module catalog")
    allowed = set(expected if group == "all" else GROUPS[group])
    return [p for p in roots if p.relative_to(candidate).as_posix() in allowed]


def merge_reports(reports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if set(reports) != set(GROUPS):
        raise ValueError("contract evidence missing or unexpected group")
    files = runs = 0
    for group, names in GROUPS.items():
        report = reports[group]
        inventory = report.get("checked_roots")
        if (
            report.get("status") != "passed"
            or report.get("phase") != "contracts"
            or report.get("contract_group") != group
            or not isinstance(inventory, dict)
            or set(inventory) != set(names)
        ):
            raise ValueError("contract evidence group/root identity mismatch")
        for root, counts in inventory.items():
            if (
                not isinstance(counts, dict)
                or set(counts) != {"files", "passed"}
                or any(type(counts[k]) is not int or counts[k] < 0 for k in counts)
                or (not root.startswith("environments/") and min(counts.values()) <= 0)
            ):
                raise ValueError("contract evidence invalid per-root counters")
        totals = {k: sum(v[k] for v in inventory.values()) for k in ("files", "passed")}
        if (
            type(report.get("contract_files")) is not int
            or type(report.get("contract_runs")) is not int
            or totals["files"] != report["contract_files"]
            or totals["passed"] != report["contract_runs"]
            or min(totals.values()) <= 0
        ):
            raise ValueError("contract evidence totals differ from executed roots")
        files += totals["files"]
        runs += totals["passed"]
    return {
        "status": "passed",
        "phase": "contracts",
        "contract_files": files,
        "contract_runs": runs,
        "contract_groups": reports,
    }
