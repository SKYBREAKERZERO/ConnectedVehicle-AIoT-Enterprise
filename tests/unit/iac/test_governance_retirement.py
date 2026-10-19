from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.governance_retirement import publish, review

COMMIT = "a" * 40
ADDRESS = 'module.governance.aws_organizations_policy_attachment.environment["dev"]'


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    identity = {
        "id": "p-test:ou-abcd-abcdefgh",
        "policy_id": "p-test",
        "target_id": "ou-abcd-abcdefgh",
    }
    manifest = {
        "version": 1,
        "operation_id": "b" * 32,
        "actor": "test-operator",
        "reason": "Approved OU governance handoff",
        "source_commit": COMMIT,
        "phase": "detach",
        "resources": [{"address": ADDRESS, **identity}],
    }
    plan = {
        "format_version": "1.2",
        "complete": True,
        "planned_values": {},
        "resource_changes": [
            {
                "address": ADDRESS,
                "type": "aws_organizations_policy_attachment",
                "change": {
                    "actions": ["delete"],
                    "before": identity,
                    "after": None,
                    "after_unknown": {},
                },
            }
        ],
    }
    return plan, manifest


def test_exact_review_does_not_apply_or_claim_enforcement() -> None:
    plan, manifest = fixture()
    assert review(plan, manifest, COMMIT)["status"] == "reviewed-not-applied"


@pytest.mark.parametrize("field", ["actor", "reason", "operation_id", "source_commit"])
def test_missing_review_identity_rejected(field: str) -> None:
    plan, manifest = fixture()
    manifest[field] = ""
    with pytest.raises(ValueError):
        review(plan, manifest, COMMIT)


@pytest.mark.parametrize("actions", [["create", "delete"], ["forget"], ["update"], ["no-op"]])
def test_only_exact_deletions_permitted(actions: list[str]) -> None:
    plan, manifest = fixture()
    plan["resource_changes"][0]["change"]["actions"] = actions
    with pytest.raises(ValueError):
        review(plan, manifest, COMMIT)


def test_unexpected_deletion_and_identity_mismatch_rejected() -> None:
    plan, manifest = fixture()
    extra = deepcopy(plan["resource_changes"][0])
    extra["address"] = ADDRESS.replace("dev", "prod")
    plan["resource_changes"].append(extra)
    with pytest.raises(ValueError):
        review(plan, manifest, COMMIT)
    plan, manifest = fixture()
    plan["resource_changes"][0]["change"]["before"]["target_id"] = "ou-other-abcdefgh"
    with pytest.raises(ValueError):
        review(plan, manifest, COMMIT)


def test_publish_never_overwrites_prior_evidence(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    publish(path, {"status": "first"})
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        publish(path, {"status": "second"})
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "change", ["commit", "duplicate", "incomplete", "bool-version", "wrong-phase"]
)
def test_corrupt_retirement_review_rejected(change: str) -> None:
    plan, manifest = fixture()
    if change == "commit":
        manifest["source_commit"] = "c" * 40
    elif change == "duplicate":
        manifest["resources"].append(deepcopy(manifest["resources"][0]))
    elif change == "incomplete":
        plan["complete"] = False
    elif change == "bool-version":
        manifest["version"] = True
    else:
        manifest["phase"] = "delete-all"
    with pytest.raises(ValueError):
        review(plan, manifest, COMMIT)
