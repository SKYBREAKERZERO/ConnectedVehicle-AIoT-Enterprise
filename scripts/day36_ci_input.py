"""Read-only branch-local CI audit. This is NOT trusted-main release promotion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.iac.plan_admission import canonical_digest, ruleset_errors
from scripts.iac.workflow_evidence_binding import GitHub, inspect_ci


def observe_governance(rules: dict[str, Any]) -> dict[str, Any]:
    # A local container test may run with incomplete governance visibility.
    # Still reject any visible weakening; never infer an empty bypass list.
    if (
        rules.get("target") != "branch"
        or rules.get("enforcement") != "active"
        or rules.get("conditions") != {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
    ):
        raise ValueError("Visible main protection is not active for the expected branch")
    reviews = [r["parameters"] for r in rules["rules"] if r["type"] == "pull_request"]
    checks = [r["parameters"] for r in rules["rules"] if r["type"] == "required_status_checks"]
    if (
        len(reviews) != 1
        or type(reviews[0]["required_approving_review_count"]) is not int
        or reviews[0]["required_approving_review_count"] < 1
        or any(
            reviews[0].get(k) is not True
            for k in (
                "dismiss_stale_reviews_on_push",
                "require_last_push_approval",
                "required_review_thread_resolution",
            )
        )
        or len(checks) != 1
        or checks[0].get("strict_required_status_checks_policy") is not True
        or checks[0].get("do_not_enforce_on_create") is not False
        or {(c["context"], c["integration_id"]) for c in checks[0]["required_status_checks"]}
        != {("IaC quality gate", 15368), ("Runtime quality gate", 15368)}
        or not {"deletion", "non_fast_forward"} <= {r["type"] for r in rules["rules"]}
    ):
        raise ValueError("Visible review or required-check protection was weakened")
    visible = "bypass_actors" in rules
    if visible and ruleset_errors(rules):
        raise ValueError("Visible main governance does not satisfy protected-release policy")
    return {
        "status": "CONFIGURATION_VERIFIED" if visible else "UNOBSERVABLE",
        "bypass_actors_visible": visible,
        "ruleset_sha256": canonical_digest(rules),
        "release_approval_verified": False,
        "trusted_main_release_verified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    api = GitHub()
    observed = observe_governance(api.get("rulesets/24828733"))
    result = inspect_ci(api, args.pr)
    if observe_governance(api.get("rulesets/24828733")) != observed:
        raise ValueError("Observed governance changed during CI audit")
    result["governance_observation"] = observed
    result["trusted_main_release_verified"] = False
    result["verification_mode"] = "branch-local-staging-precheck"
    result["production_authorized"] = False
    if args.compare and json.loads(args.compare.read_text()) != result:
        raise ValueError("CI evidence, candidate or governance changed during staging")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
