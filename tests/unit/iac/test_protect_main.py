from __future__ import annotations

from scripts.iac.protect_main import (
    REQUIRED_CHECK,
    REQUIRED_CHECKS,
    protection_errors,
    protection_payload,
)


def test_existing_requirements_are_preserved_and_iac_added() -> None:
    actual = protection_payload(
        {
            "required_status_checks": {
                "contexts": ["Python tests"],
                "checks": [{"context": "Python tests", "app_id": 123}],
            },
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "require_code_owner_reviews": True,
            },
            "restrictions": {"users": [{"login": "existing-maintainer"}], "teams": [], "apps": []},
        }
    )
    checks = actual["required_status_checks"]["checks"]
    assert {c["context"] for c in checks} == {"Python tests", *REQUIRED_CHECKS}
    assert next(c for c in checks if c["context"] == "Python tests")["app_id"] == 123
    assert actual["required_pull_request_reviews"]["required_approving_review_count"] == 2
    assert actual["required_pull_request_reviews"]["require_code_owner_reviews"]
    assert actual["restrictions"]["users"] == ["existing-maintainer"]
    assert actual["enforce_admins"]
    assert actual["required_status_checks"]["strict"]
    assert not actual["allow_force_pushes"]


def test_reapplying_protection_does_not_duplicate_check() -> None:
    current = {
        "required_status_checks": {
            "contexts": [REQUIRED_CHECK],
            "checks": [{"context": REQUIRED_CHECK, "app_id": 15368}],
        }
    }
    checks = protection_payload(current)["required_status_checks"]["checks"]
    assert checks == [{"context": name, "app_id": 15368} for name in REQUIRED_CHECKS]


def test_verify_requires_both_gates_and_actions_identity() -> None:
    current = protection_payload({})
    current["enforce_admins"] = {"enabled": True}
    current["allow_force_pushes"] = {"enabled": False}
    current["allow_deletions"] = {"enabled": False}
    assert protection_errors(current) == []
    current["required_status_checks"]["checks"].pop()
    assert any("Runtime quality gate" in error for error in protection_errors(current))
