"""Same-attempt cross-job data bundles and fail-closed DAG completion checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from scripts.iac.day31_evidence import provenance


def step_summary(title: str, rows: list[tuple[str, str]]) -> None:
    if name := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(name).open("a", encoding="utf-8") as out:
            out.write("### " + title + "\n\n| Item | Result |\n|---|---|\n")
            for key, value in rows:
                out.write(f"| {key} | {value} |\n")
            out.write("\n")


def require_needs(expected: set[str], data: dict[str, Any]) -> None:
    step_summary(
        "Mandatory pipeline nodes",
        [(k, str(data.get(k, {}).get("result", "missing"))) for k in sorted(expected)],
    )
    if set(data) != expected or any(v.get("result") != "success" for v in data.values()):
        raise ValueError(
            "all mandatory DAG nodes must succeed; failure/cancel/skip/missing denies gate"
        )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish(folder: Path, output: Path, stage: str) -> None:
    if not re.fullmatch("[a-z][a-z0-9-]+", stage):
        raise ValueError("bounded fixed stage required")
    files = {}
    for path in folder.iterdir():
        if path.is_file() and path.suffix in {".json", ".xml"} and path.name != "manifest.json":
            if path.is_symlink() or not re.fullmatch("[a-z0-9_-]+[.](json|xml)", path.name):
                raise ValueError("unsafe report name")
            files[path.name] = sha(path)
    if not files:
        raise ValueError("empty stage evidence")
    output.mkdir(parents=True, exist_ok=False)
    for name in files:
        shutil.copyfile(folder / name, output / name)
    step_summary(
        "Evidence sealed",
        [
            ("Stage", stage),
            ("Candidate", provenance()["day31_commit"]),
            ("Run / attempt", provenance()["day31_run_id"]),
            ("Hashed reports", str(len(files))),
        ],
    )
    (output / "manifest.json").write_text(
        json.dumps(
            {"version": 1, "stage": stage, "provenance": provenance(), "files": files},
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def verify(folder: Path, stage: str) -> dict[str, str]:
    m = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if (
        set(m) != {"version", "stage", "provenance", "files"}
        or type(m["version"]) is not int
        or m["version"] != 1
        or m["stage"] != stage
        or m["provenance"] != provenance()
    ):
        raise ValueError("stage/source/commit/run/attempt mismatch")
    files = m["files"]
    if not files or set(p.name for p in folder.iterdir()) != set(files) | {"manifest.json"}:
        raise ValueError("missing or additional artifact members")
    for name, wanted in files.items():
        path = folder / name
        if (
            not re.fullmatch("[a-z0-9_-]+[.](json|xml)", name)
            or path.is_symlink()
            or not path.is_file()
            or sha(path) != wanted
        ):
            raise ValueError("corrupt stage evidence")
    return dict(files)


def consume(folder: Path, stage: str, output: Path) -> None:
    files = verify(folder, stage)
    output.mkdir(parents=True, exist_ok=True)
    for name in files:
        target = output / name
        if target.exists() and sha(target) != files[name]:
            raise ValueError("conflicting evidence from independent jobs")
        shutil.copyfile(folder / name, target)


def assemble_iac(inputs: Path, output: Path) -> None:
    for stage in ("iac-policy", "iac-contracts", "iac-security", "iac-native"):
        consume(inputs / stage, stage, output)
    contracts = json.loads((output / "contracts.json").read_text())
    security = json.loads((output / "security.json").read_text())
    native = json.loads((output / "summary.json").read_text())
    if (
        contracts.get("phase") != "contracts"
        or contracts.get("status") != "passed"
        or contracts.get("contract_runs", 0) <= 0
        or contracts.get("contract_files", 0) <= 0
    ):
        raise ValueError("no real Terraform contract evidence")
    if security != {
        "status": "passed",
        "phase": "security",
        "security_scan": "passed",
        "scanned_sources": 2,
    }:
        raise ValueError("security scan evidence incomplete")
    if (
        native.get("phase") != "native"
        or native.get("status") != "passed"
        or native.get("security_scan") != "separate-job-required"
    ):
        raise ValueError("native phase cannot impersonate separate checks")
    native.update(
        contract_files=contracts["contract_files"],
        contract_runs=contracts["contract_runs"],
        security_scan=security["security_scan"],
        phase="assembled-dag",
        phase_report_sha256={
            name: sha(output / name) for name in ("contracts.json", "security.json")
        },
    )
    (output / "summary.json").write_text(
        json.dumps(native, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("publish", "consume", "verify", "needs", "assemble-iac"))
    p.add_argument("--folder", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--stage")
    p.add_argument("--expected")
    a = p.parse_args()
    if a.command == "needs":
        if not a.expected:
            raise ValueError("expected DAG nodes required")
        require_needs(set(a.expected.split(",")), json.loads(os.environ["PIPELINE_NEEDS"]))
    elif a.command == "publish":
        if a.folder is None or a.output is None or a.stage is None:
            raise ValueError("publish arguments required")
        publish(a.folder, a.output, a.stage)
    elif a.command == "consume":
        if a.folder is None or a.output is None or a.stage is None:
            raise ValueError("consume arguments required")
        consume(a.folder, a.stage, a.output)
    elif a.command == "verify":
        if a.folder is None or a.stage is None:
            raise ValueError("verify arguments required")
        verify(a.folder, a.stage)
    else:
        if a.folder is None or a.output is None:
            raise ValueError("assembly arguments required")
        assemble_iac(a.folder, a.output)
    print("Pipeline stage identity/integrity check PASS")


if __name__ == "__main__":
    main()
