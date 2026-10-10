from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import Any

REQUIRED_CHECK = "IaC quality gate"
REQUIRED_CHECKS = (REQUIRED_CHECK, "Runtime quality gate")
GITHUB_ACTIONS_APP_ID = 15368


def protection_payload(current: dict[str, Any]) -> dict[str, Any]:
    """Preserve existing branch requirements while adding the IaC check."""
    old_status = current.get("required_status_checks") or {}
    checks = list(old_status.get("checks") or [])
    contexts = set(old_status.get("contexts") or []) | {check["context"] for check in checks}
    for required in REQUIRED_CHECKS:
        if required not in contexts or not any(check["context"] == required for check in checks):
            checks.append({"context": required, "app_id": GITHUB_ACTIONS_APP_ID})
    for context in old_status.get("contexts") or []:
        if not any(check["context"] == context for check in checks):
            checks.append({"context": context})
    for check in checks:
        if check["context"] in REQUIRED_CHECKS:
            check["app_id"] = GITHUB_ACTIONS_APP_ID
    review = current.get("required_pull_request_reviews") or {}
    reviews: dict[str, Any] = {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "required_approving_review_count": max(1, review.get("required_approving_review_count", 0)),
        "require_last_push_approval": True,
    }
    for name in ("dismissal_restrictions", "bypass_pull_request_allowances"):
        if review.get(name):
            # Only logins/slugs, never API URLs or numeric identifiers.
            reviews[name] = identities(review[name])
    restrictions = current.get("restrictions")
    payload: dict[str, Any] = {
        "required_status_checks": {"strict": True, "checks": checks},
        "enforce_admins": True,
        "required_pull_request_reviews": reviews,
        "restrictions": identities(restrictions) if restrictions else None,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }
    for name in ("required_linear_history", "block_creations", "lock_branch", "allow_fork_syncing"):
        if name in current:
            payload[name] = bool(current[name].get("enabled", False))
    return payload


def protection_errors(current: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    status = current.get("required_status_checks") or {}
    checks = {item["context"]: item.get("app_id") for item in status.get("checks", [])}
    for required in REQUIRED_CHECKS:
        if checks.get(required) != GITHUB_ACTIONS_APP_ID:
            errors.append(f"missing or untrusted required check: {required}")
    for name, value in (
        ("strict status checks", status.get("strict")),
        ("administrator enforcement", (current.get("enforce_admins") or {}).get("enabled")),
        ("pull request reviews", current.get("required_pull_request_reviews")),
    ):
        if not value:
            errors.append(name)
    for name in ("allow_force_pushes", "allow_deletions"):
        if (current.get(name) or {}).get("enabled", False):
            errors.append(name)
    return errors


def identities(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "users": [item["login"] for item in value.get("users", [])],
        "teams": [item["slug"] for item in value.get("teams", [])],
        "apps": [item["slug"] for item in value.get("apps", [])],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require IaC quality gate on main (GitHub admin access)"
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument(
        "--verify", action="store_true", help="Read and verify protection without writes"
    )
    parser.add_argument(
        "--apply", action="store_true", help="Write protection; default only previews JSON"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be OWNER/REPO")
    endpoint = f"repos/{args.repo}/branches/main/protection"
    read = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True, check=False)
    if read.returncode and "HTTP 404" not in read.stderr:
        print("Cannot read GitHub branch protection. Authenticate gh with repository admin access.")
        return 1
    current = json.loads(read.stdout) if read.returncode == 0 else {}
    if args.verify:
        problems = protection_errors(current)
        if problems:
            print("Branch protection FAILED: " + "; ".join(problems))
            return 1
        print("Both required gates and branch protection verified.")
        return 0
    payload = protection_payload(current)
    if not args.apply:
        print(json.dumps(payload, indent=2))
        return 0
    write = subprocess.run(
        ["gh", "api", "--method", "PUT", endpoint, "--input", "-"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    if write.returncode:
        print("Branch protection update failed; check repository admin permissions.")
        return 1
    actual = json.loads(write.stdout)
    if protection_errors(actual):
        print("GitHub did not confirm the required check; inspect branch protection.")
        return 1
    print("main now requires both quality gates, reviews and an up-to-date branch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
