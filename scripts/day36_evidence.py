"""Fail-closed local staging proof verification. Grants no release authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from scripts.day35_workflow_gate import load
from scripts.day36_build import application_hash
from scripts.day36_staging import ROOT, command

REQUIRED = {
    "test_staging_fault[startup_exit]",
    "test_staging_fault[readiness_503]",
    "test_staging_fault[candidate_sigkill]",
    "test_staging_data_and_identity",
    "test_staging_image_permissions",
}
FILES = ("images.json", "staging.json", "staging.xml")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(folder: Path, ci: bool = False) -> dict[str, Any]:
    images, staging = load(folder / "images.json"), load(folder / "staging.json")
    candidate = command(["git", "rev-parse", "HEAD"])
    if (
        images["candidate_sha"] != candidate
        or staging["candidate_sha"] != candidate
        or staging["environment"] != "local_staging"
        or staging["production_authorized"] is not False
        or images["candidate"]["revision"] != candidate
        or images["candidate"]["application_sha256"] != application_hash(ROOT)
    ):
        raise ValueError("Source, environment or authorization mismatch")
    run, attempt = (
        os.environ.get("GITHUB_RUN_ID", "local"),
        os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    )
    if staging["run_id"] != run or staging["run_attempt"] != attempt:
        raise ValueError("Stale staging Run/Attempt")
    age = (datetime.now(UTC) - datetime.fromisoformat(staging["generated_at"])).total_seconds()
    if not 0 <= age <= 7200:
        raise ValueError("Stale or future staging evidence")
    for role, field in (("baseline", "baseline_image_digest"), ("candidate", "image_digest")):
        image = images[role]
        if not re.fullmatch("sha256:[0-9a-f]{64}", image["image_digest"]):
            raise ValueError("Invalid immutable image ID")
        if staging[field] != image["image_digest"]:
            raise ValueError("Deployment/build image mismatch")
    if staging["baseline_image_digest"] == staging["image_digest"]:
        raise ValueError("No distinct candidate upgrade was exercised")
    if (
        staging["before"] != staging["after"]
        or staging["before"]["remote_commands"]["count"] != 1
        or staging["before"]["outbox_events"]["count"] != 1
        or staging["schema_rollback_executed"] is not False
        or any(
            staging[name] is not True
            for name in (
                "rollback_verified",
                "database_consistency_verified",
                "stable_ingress_verified",
                "runtime_security_verified",
            )
        )
        or set(staging["smoke_test"]) != {"authenticated_command", "campaign_query"}
        or any(value is not True for value in staging["smoke_test"].values())
    ):
        raise ValueError("Missing real smoke, rollback, role or consistency proof")
    faults = staging["faults"]
    if (
        len(faults) != 3
        or {f["name"] for f in faults} != {"startup_exit", "readiness_503", "candidate_sigkill"}
        or any(f["rejected"] is not True or f["rollback_verified"] is not True for f in faults)
    ):
        raise ValueError("Incomplete mandatory failure matrix")
    xml = folder / "staging.xml"
    if xml.is_symlink() or xml.stat().st_size > 3_000_000:
        raise ValueError("Unsafe JUnit input")
    data = xml.read_bytes()
    if b"<!" in data:
        raise ValueError("JUnit declarations forbidden")
    tree = ET.fromstring(data)
    cases = tree.findall(".//testcase")
    if len(cases) != len(REQUIRED) or {c.get("name") for c in cases} != REQUIRED:
        raise ValueError("Missing or duplicate mandatory staging tests")
    expected = {
        "candidate_sha": candidate,
        "run_id": run,
        "run_attempt": attempt,
        "staging_sha256": digest(folder / "staging.json"),
    }
    for case in cases:
        properties = case.findall("./properties/property")
        if (
            any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
            or len(properties) != len(expected)
            or {p.get("name"): p.get("value") for p in properties} != expected
        ):
            raise ValueError("Failed/skipped/unbound staging test")
    result: dict[str, Any] = {
        "decision": "LOCAL_STAGING_VERIFIED",
        "environment": "local_staging",
        "candidate_sha": candidate,
        "run_id": run,
        "run_attempt": attempt,
        "image_digest": staging["image_digest"],
        "rollback_verified": True,
        "database_consistency_verified": True,
        "production_authorized": False,
        "release_authorized": False,
        "trusted_main_release_verified": False,
        "proofs": {name: digest(folder / name) for name in FILES},
        "required_cases": sorted(REQUIRED),
    }
    if ci:
        before, after = load(folder / "ci-input.json"), load(folder / "ci-final.json")
        if (
            before != after
            or before["candidate"]["candidate_sha"] != candidate
            or before["release_authorized"] is not False
            or before["apply_authorized"] is not False
            or before["verification_mode"] != "branch-local-staging-precheck"
            or set(before["workflows"])
            != {".github/workflows/runtime.yml", ".github/workflows/ci.yml"}
            or any(w["candidate_sha"] != candidate for w in before["workflows"].values())
        ):
            raise ValueError("CI identity or latest-attempt snapshot mismatch")
        observation = before["governance_observation"]
        if (
            type(observation["bypass_actors_visible"]) is not bool
            or observation["status"]
            != (
                "CONFIGURATION_VERIFIED" if observation["bypass_actors_visible"] else "UNOBSERVABLE"
            )
            or observation["release_approval_verified"] is not False
            or observation["trusted_main_release_verified"] is not False
            or before["trusted_main_release_verified"] is not False
            or before["production_authorized"] is not False
        ):
            raise ValueError("Local staging cannot infer governance visibility or approval")
        result["governance_observation"] = observation
        result["upstream_workflows"] = before["workflows"]
        result["decision"] = "READY_FOR_STAGING_REVIEW"
        result["proofs"].update(
            {name: digest(folder / name) for name in ("ci-input.json", "ci-final.json")}
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.folder, args.ci)
    except (ValueError, OSError, KeyError, TypeError, ET.ParseError) as error:
        result = {
            "decision": "BLOCKED",
            "production_authorized": False,
            "release_authorized": False,
            "reason": str(error),
        }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    if result["decision"] == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
