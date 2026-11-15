"""Event-bound baseline selection. No zero/self/current-HEAD fallback."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPOSITORY = "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"


def sha(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch("[0-9a-f]{40}", value) is None
        or value == "0" * 40
    ):
        raise ValueError("nonzero full commit SHA required")
    return value


def select_baseline(
    *,
    event_name: str,
    event: dict[str, Any],
    candidate: str,
    ref: str,
    parents: list[str],
    ancestor: Callable[[str, str], bool],
    default_tip: str,
) -> dict[str, Any]:
    candidate = sha(candidate)
    repository = event["repository"]
    if repository["full_name"] != REPOSITORY or repository["default_branch"] != "main":
        raise ValueError("reviewed repository/default branch required")
    result: dict[str, Any] = {
        "repository": REPOSITORY,
        "event": event_name,
        "ref": ref,
        "candidate_sha": candidate,
        "pr_number": None,
        "pr_head_sha": None,
    }
    if event_name == "pull_request":
        pr = event["pull_request"]
        number = event["number"]
        # GITHUB_SHA + actual Git parents identify this event candidate. The PR
        # payload merge_commit_sha cache can describe an earlier background merge.
        baseline = sha(pr["base"]["sha"])
        head = sha(pr["head"]["sha"])
        if (
            type(number) is not int
            or number <= 0
            or ref != f"refs/pull/{number}/merge"
            or pr["base"]["repo"]["full_name"] != REPOSITORY
            or pr["base"]["ref"] != "main"
            or pr["state"] != "open"
            or parents != [baseline, head]
        ):
            raise ValueError("PR merge identity/parents mismatch")
        result.update(pr_number=number, pr_head_sha=head)
    elif event_name == "push":
        baseline = sha(event["before"])
        if (
            ref != "refs/heads/main"
            or event["ref"] != ref
            or sha(event["after"]) != candidate
            or event.get("forced") is not False
            or event.get("created") is not False
            or event.get("deleted") is not False
        ):
            raise ValueError("only non-forced existing main push accepted")
    elif event_name == "merge_group":
        group = event["merge_group"]
        baseline = sha(group["base_sha"])
        if (
            group["head_sha"] != candidate
            or group["base_ref"] != "refs/heads/main"
            or group["head_ref"] != ref
            or not ref.startswith("refs/heads/gh-readonly-queue/main/")
        ):
            raise ValueError("merge queue target/head mismatch")
    elif event_name == "workflow_dispatch":
        if (
            ref != "refs/heads/main"
            or sha(default_tip) != candidate
            or event.get("inputs")
            or not parents
        ):
            raise ValueError("manual run must use current main; baseline overrides denied")
        baseline = sha(parents[0])
    else:
        raise ValueError("unsupported event; no fallback baseline")
    if baseline == candidate or not ancestor(baseline, candidate):
        raise ValueError("baseline must be a distinct ancestor of candidate")
    result["baseline_sha"] = baseline
    return result


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def current() -> dict[str, Any]:
    candidate = sha(os.environ["GITHUB_SHA"])
    if git("rev-parse", "HEAD") != candidate:
        raise ValueError("checkout differs from event candidate")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = select_baseline(
        event_name=os.environ["GITHUB_EVENT_NAME"],
        event=event,
        candidate=candidate,
        ref=os.environ["GITHUB_REF"],
        parents=git("show", "-s", "--format=%P", candidate).split(),
        ancestor=lambda a, b: (
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", a, b], capture_output=True
            ).returncode
            == 0
        ),
        default_tip=git("rev-parse", "refs/remotes/origin/main"),
    )
    result.update(
        run_id=int(os.environ["GITHUB_RUN_ID"]),
        run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        selector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    if result["run_id"] <= 0 or result["run_attempt"] <= 0:
        raise ValueError("positive run identity required")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = current()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as f:
            f.write("ref=" + result["baseline_sha"] + "\n")
    print("Event-bound distinct ancestor baseline verified")


if __name__ == "__main__":
    main()
