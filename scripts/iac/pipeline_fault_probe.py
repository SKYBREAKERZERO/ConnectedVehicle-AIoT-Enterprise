"""Isolated Actions scheduler/artifact fault probes; never a deployment authority."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from scripts.iac.pipeline_evidence import publish, require_needs

SCENARIOS = ("failure", "skipped", "missing-artifact", "tamper", "old-attempt")


def verify_outcomes(scenario: str, needs: dict[str, Any]) -> None:
    if scenario not in SCENARIOS or set(needs) != {"producer", "consumer"}:
        raise ValueError("unknown fault or missing scheduler evidence")
    producer = "skipped" if scenario == "skipped" else "success"
    step = (
        "guard"
        if scenario in {"failure", "skipped"}
        else "download"
        if scenario == "missing-artifact"
        else "verify"
    )
    if (
        needs["producer"]["result"] != producer
        or needs["consumer"]["result"] != "success"
        or needs["consumer"]["outputs"].get(step) != "failure"
        or (
            scenario != "skipped"
            and needs["producer"]["outputs"].get("operation")
            != ("failure" if scenario == "failure" else "success")
        )
        or (step != "guard" and needs["consumer"]["outputs"].get("guard") != "success")
        or (step == "verify" and needs["consumer"]["outputs"].get("download") != "success")
    ):
        raise ValueError("fault was not blocked at its intended boundary")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("produce", "guard", "check"))
    args = parser.parse_args()
    scenario = os.environ["FAULT_SCENARIO"]
    graph = os.environ["FAULT_GRAPH"]
    if graph not in {"runtime", "iac"} or scenario not in SCENARIOS:
        raise ValueError("fixed isolated fault scope required")
    if args.mode == "guard":
        # Expected-failure allowances mask the job result in this harness only.
        # Propagate actual process outcomes into the unchanged production checker.
        producer = json.loads(os.environ["FAULT_NEEDS"])["producer"]
        result = producer["result"]
        if result == "success":
            result = producer["outputs"].get("operation")
        require_needs({"producer"}, {"producer": {"result": result}})
    elif args.mode == "produce":
        if scenario == "failure":
            raise RuntimeError("intentional isolated producer failure")
        reports = Path(".fault-reports")
        reports.mkdir()
        (reports / "probe.json").write_text('{"isolated_fixture":true}', encoding="utf-8")
        output = Path(".fault-bundle")
        publish(reports, output, "runtime-core" if graph == "runtime" else "iac-policy")
        if scenario == "old-attempt":
            # Retain an authentic first-attempt bundle for a real subsequent rerun.
            publish(
                reports,
                Path(".fault-history"),
                "runtime-core" if graph == "runtime" else "iac-policy",
            )
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
            "historical_input_attempt": os.environ.get("FAULT_HISTORY_ATTEMPT") or None,
            "observed_needs": needs,
            "fault_blocked": "failure" in needs["consumer"]["outputs"].values(),
            "deployment_authorized": False,
        }
        Path("fault-result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Expected fault blocked; no deployment authorization")


if __name__ == "__main__":
    main()
