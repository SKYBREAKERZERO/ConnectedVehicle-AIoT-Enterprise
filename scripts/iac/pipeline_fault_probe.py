"""Isolated Actions scheduler/artifact fault probes; never a deployment authority."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from scripts.iac.pipeline_evidence import publish

SCENARIOS = ("failure", "skipped", "missing-artifact", "tamper", "old-attempt")


def verify_outcomes(scenario: str, needs: dict[str, Any]) -> None:
    if scenario not in SCENARIOS or set(needs) != {"producer", "consumer"}:
        raise ValueError("unknown fault or missing scheduler evidence")
    producer = (
        "failure" if scenario == "failure" else "skipped" if scenario == "skipped" else "success"
    )
    step = (
        "guard"
        if scenario in {"failure", "skipped"}
        else "download"
        if scenario == "missing-artifact"
        else "verify"
    )
    if (
        needs["producer"]["result"] != producer
        or needs["consumer"]["result"] != "failure"
        or needs["consumer"]["outputs"].get(step) != "failure"
    ):
        raise ValueError("fault was not blocked at its intended boundary")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("produce", "check"))
    args = parser.parse_args()
    scenario = os.environ["FAULT_SCENARIO"]
    graph = os.environ["FAULT_GRAPH"]
    if graph not in {"runtime", "iac"} or scenario not in SCENARIOS:
        raise ValueError("fixed isolated fault scope required")
    if args.mode == "produce":
        if scenario == "failure":
            raise RuntimeError("intentional isolated producer failure")
        reports = Path(".fault-reports")
        reports.mkdir()
        (reports / "probe.json").write_text('{"isolated_fixture":true}', encoding="utf-8")
        output = Path(".fault-bundle")
        publish(reports, output, "runtime-core" if graph == "runtime" else "iac-policy")
        if scenario == "tamper":
            (output / "probe.json").write_text('{"changed":true}', encoding="utf-8")
        if scenario == "old-attempt":
            path = output / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["provenance"]["day31_run_id"] = os.environ["GITHUB_RUN_ID"] + ":0"
            path.write_text(json.dumps(manifest), encoding="utf-8")
    else:
        needs = json.loads(os.environ["FAULT_NEEDS"])
        verify_outcomes(scenario, needs)
        report = {
            "scope": "isolated-actions-scheduler-and-artifact-probe",
            "graph": graph,
            "scenario": scenario,
            "commit": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"],
            "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "observed_needs": needs,
            "fault_blocked": needs["consumer"]["result"] == "failure",
            "deployment_authorized": False,
        }
        Path("fault-result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Expected fault blocked; no deployment authorization")


if __name__ == "__main__":
    main()
