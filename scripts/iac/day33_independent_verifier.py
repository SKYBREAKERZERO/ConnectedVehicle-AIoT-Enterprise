"""Independent, read-only Day33 artifact admission; never grants deployment authority."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.iac.workflow_evidence_binding import unpack

REQUIRED_JOBS = frozenset(
    {
        "01 IaC baseline and candidate",
        "02 IaC lint and format",
        "03 IaC type safety",
        "04 Policy and trust contracts",
        "06 Checkov and policy audit / Isolated Terraform phase",
        "07 LocalStack deploy and recovery / Isolated Terraform phase",
        "08 IaC evidence verification",
        "09 Day32 deployment acceptance",
        "IaC quality gate",
        *{
            f"05 Terraform modules ({group}) / Isolated Terraform phase"
            for group in ("foundation", "ota", "governance", "roots")
        },
    }
)


def verify_run(run: dict[str, Any], jobs: list[dict[str, Any]], head: str, attempt: int) -> None:
    """Require the caller's frozen candidate and latest API attempt, with all DAG jobs."""
    if (
        run.get("head_sha") != head
        or run.get("run_attempt") != attempt
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise ValueError("latest run/candidate/attempt is not successful")
    if (
        len(jobs) != 13
        or {j.get("name") for j in jobs} != REQUIRED_JOBS
        or any(j.get("status") != "completed" or j.get("conclusion") != "success" for j in jobs)
        or not any(j.get("name") == "IaC quality gate" for j in jobs)
    ):
        raise ValueError("mandatory DAG jobs missing, cancelled or unsuccessful")


def verify_artifact(
    raw: bytes, metadata: dict[str, Any], run: dict[str, Any], candidate: str
) -> dict[str, Any]:
    files = unpack(raw, metadata, run)
    if metadata.get("name") != "day32-iac-acceptance" or set(files) != {
        "day32-acceptance.json",
        "day32-deployment.json",
        "contracts.json",
        "summary.json",
    }:
        raise ValueError("unexpected acceptance artifact members")
    report = json.loads(files["day32-acceptance.json"])
    p = report.get("provenance", {})
    if (
        p.get("day31_commit") != candidate
        or p.get("day31_run_id") != f"{run['id']}:{run['run_attempt']}"
        or report.get("status") != "passed"
        or report.get("production_apply_enabled") is not False
        or report.get("release_authorized") is not False
    ):
        raise ValueError("artifact provenance or authority mismatch")
    for name in ("contracts.json", "summary.json", "day32-deployment.json"):
        if report.get("proof_sha256", {}).get(name) != hashlib.sha256(files[name]).hexdigest():
            raise ValueError("acceptance proof hash mismatch")
    return dict(report)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    folder = args.directory

    def load(name: str) -> Any:
        return json.loads((folder / name).read_text(encoding="utf-8"))

    context = load("context.json")
    run = load("run.json")
    verify_run(run, load("jobs.json"), context["head_sha"], context["latest_attempt"])
    report = verify_artifact(
        (folder / "acceptance.zip").read_bytes(),
        load("artifact.json"),
        run,
        context["candidate_sha"],
    )
    print(
        json.dumps(
            {
                "artifact_verified": True,
                "provenance": report["provenance"],
                "release_authorized": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
