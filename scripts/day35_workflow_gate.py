"""Event-bound Day35 admission. CI evidence never grants deployment authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day34_evidence import COMMANDS, binding, fresh
from scripts.day35_evidence import REQUIRED
from scripts.iac.ci_baseline_policy import current
from scripts.iac.day31_evidence import xml_cases
from scripts.iac.pipeline_evidence import require_needs, verify

PROOFS = {"day35-runtime-faults.xml", "day34-acceptance.json"}
PRIOR_PROOFS = {
    "day18-ota-execution.json",
    "day19-campaign.json",
    "day21-postgres.xml",
    "day34-quality.json",
}


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value: str) -> Any:
    raise ValueError("nonfinite JSON value")


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 3_000_000:
        raise ValueError("missing, linked or oversized JSON")
    with path.open("rb") as stream:
        raw = stream.read(3_000_001)
    if len(raw) > 3_000_000:
        raise ValueError("JSON read exceeds bound")
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def bounded(folder: Path) -> None:
    if folder.is_symlink() or folder.is_junction() or not folder.is_dir():
        raise ValueError("real evidence directory required")
    entries = list(folder.iterdir())
    if len(entries) > 128:
        raise ValueError("too many evidence members")
    size = 0
    for path in entries:
        if (
            path.is_symlink()
            or not path.is_file()
            or not re.fullmatch(r"[a-z0-9_-]+\.(json|xml)", path.name)
        ):
            raise ValueError("unsafe evidence member")
        size += path.stat().st_size
        if path.suffix == ".json":
            load(path)
    if size > 30_000_000:
        raise ValueError("evidence exceeds total bound")


def hashes(folder: Path, values: Any, names: set[str]) -> None:
    if not isinstance(values, dict) or set(values) != names:
        raise ValueError("mandatory proof set mismatch")
    for name, wanted in values.items():
        if not isinstance(wanted, str) or not re.fullmatch("[0-9a-f]{64}", wanted):
            raise ValueError("invalid SHA-256")
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != wanted:
            raise ValueError("proof bytes changed")


def receipt(record: dict[str, Any], expected: dict[str, str]) -> None:
    if (
        type(record.get("version")) is not int
        or record["version"] != 1
        or record.get("decision") != "READY_FOR_LOCAL_REVIEW"
        or record.get("provenance") != expected
        or record.get("ci_verified") is not True
        or record.get("release_authorized") is not False
        or record.get("real_aws_verified") is not False
        or record.get("physical_boot_verified") is not False
        or record.get("simulated_installation") is not True
    ):
        raise ValueError("receipt identity, result or authorization mismatch")


def evaluate(runtime: Path, intake: Path, needs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(needs, dict) or any(not isinstance(v, dict) for v in needs.values()):
        raise ValueError("invalid upstream result envelope")
    require_needs({"intake", "acceptance"}, needs)
    for folder, stage in [(runtime, "runtime-evidence"), (intake, "day35-intake")]:
        bounded(folder)
        members = verify(folder, stage)
        if stage == "day35-intake" and set(members) != {"day35-intake.json"}:
            raise ValueError("unexpected intake proof set")
    baseline = current()
    for path in [runtime / "day31-runtime-baseline.json", intake / "day35-intake.json"]:
        observed = load(path)
        if (
            observed != baseline
            or type(observed.get("run_id")) is not int
            or type(observed.get("run_attempt")) is not int
        ):
            raise ValueError("event/repository/baseline/candidate/attempt changed")
    expected = binding()
    proof = load(runtime / "day35-acceptance.json")
    receipt(proof, expected)
    fresh(proof)
    if proof.get("required_cases") != sorted(REQUIRED):
        raise ValueError("mandatory fault case declaration mismatch")
    hashes(runtime, proof.get("proofs"), PROOFS)
    xml_cases((runtime / "day35-runtime-faults.xml").read_bytes(), REQUIRED, expected, exact=True)
    prior = load(runtime / "day34-acceptance.json")
    receipt(prior, expected)
    hashes(runtime, prior.get("proofs"), PRIOR_PROOFS)
    quality = load(runtime / "day34-quality.json")
    fresh(quality)
    checks = quality.get("checks", {})
    if (
        quality.get("provenance") != expected
        or not isinstance(checks, dict)
        or set(checks) != set(COMMANDS)
        or any(
            not isinstance(c, dict)
            or type(c.get("exit_code")) is not int
            or c["exit_code"] != 0
            or not isinstance(c.get("log_sha256"), str)
            or not re.fullmatch("[0-9a-f]{64}", c["log_sha256"])
            for c in checks.values()
        )
    ):
        raise ValueError("quality source/run mismatch")
    return dict(
        version=1,
        decision="READY_FOR_LOCAL_REVIEW",
        scope="day35_branch_ci_acceptance",
        ci_verified=True,
        release_authorized=False,
        real_aws_verified=False,
        physical_boot_verified=False,
        simulated_installation=True,
        baseline=baseline,
        provenance=expected,
        required_cases=sorted(REQUIRED),
        proofs=proof["proofs"],
        manifest_sha256=hashlib.sha256((runtime / "manifest.json").read_bytes()).hexdigest(),
        intake_manifest_sha256=hashlib.sha256((intake / "manifest.json").read_bytes()).hexdigest(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path(".day35-input"))
    parser.add_argument("--intake", type=Path, default=Path(".day35-intake-input"))
    parser.add_argument("--output", type=Path, default=Path("day35-workflow-result.json"))
    args = parser.parse_args()
    if any(args.output.resolve().is_relative_to(p.resolve()) for p in [args.runtime, args.intake]):
        raise ValueError("result must not alter input evidence")
    try:
        result = evaluate(
            args.runtime,
            args.intake,
            json.loads(
                os.environ["PIPELINE_NEEDS"],
                object_pairs_hook=pairs,
                parse_constant=invalid_constant,
            ),
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        SyntaxError,
        subprocess.SubprocessError,
    ) as exc:
        result = dict(
            version=1,
            decision="BLOCKED",
            scope="day35_branch_ci_acceptance",
            ci_verified=False,
            release_authorized=False,
            real_aws_verified=False,
            physical_boot_verified=False,
            reason_code="ADMISSION_REJECTED",
            reason=(type(exc).__name__ + ": " + str(exc)).replace("\n", " ")[:500],
        )
    result["observed_context"] = {
        key: os.environ.get(key)
        for key in (
            "GITHUB_REPOSITORY",
            "GITHUB_SHA",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_EVENT_NAME",
            "GITHUB_WORKFLOW_REF",
        )
    }
    result["verifier_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["production_apply_enabled"] = False
    result["generated_at_utc"] = datetime.now(UTC).isoformat()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(
                "## Day35 admission\n\nDecision: **"
                + result["decision"]
                + "**\n\nRelease authorized: **false**.\n"
            )
    print("Day35 admission: " + result["decision"])
    return 0 if result["decision"] == "READY_FOR_LOCAL_REVIEW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
