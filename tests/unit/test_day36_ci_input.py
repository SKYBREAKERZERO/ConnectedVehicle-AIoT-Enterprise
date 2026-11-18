"""Read-only visibility must never become release governance authorization."""

from __future__ import annotations

from typing import Any

import pytest

from scripts.day36_ci_input import observe_governance
from scripts.iac.workflow_evidence_binding import GitHub, live
from tests.unit.iac.test_plan_admission import ruleset


@pytest.mark.parametrize(
    "visibility", ["complete", "redacted", "bypass", "review", "checks", "disabled"]
)
def test_local_governance_visibility_preserves_closed_release(visibility: str) -> None:
    value = ruleset()
    if visibility != "complete":
        value.pop("bypass_actors")
    if visibility == "bypass":
        value["bypass_actors"] = [{"actor_id": 1}]
    elif visibility == "review":
        value["rules"][0]["parameters"]["required_approving_review_count"] = 0
    elif visibility == "checks":
        value["rules"][1]["parameters"]["required_status_checks"] = []
    elif visibility == "disabled":
        value["enforcement"] = "disabled"
    if visibility in {"complete", "redacted"}:
        observed = observe_governance(value)
        assert observed["status"] == (
            "UNOBSERVABLE" if visibility == "redacted" else "CONFIGURATION_VERIFIED"
        )
        assert observed["release_approval_verified"] is False
        assert observed["trusted_main_release_verified"] is False
        assert observed["bypass_actors_visible"] is (visibility == "complete")
        assert ("bypass_actors" in value) is (visibility == "complete")
    else:
        with pytest.raises(ValueError):
            observe_governance(value)


def test_trusted_day31_path_still_rejects_redacted_governance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = ruleset()
    value.pop("bypass_actors")
    api = object.__new__(GitHub)

    def get(path: str) -> dict[str, Any]:
        assert path == "rulesets/24828733", "Denied before any CI admission"
        return value

    monkeypatch.setattr(api, "get", get)
    with pytest.raises(ValueError, match="main ruleset"):
        live(api, 15)
