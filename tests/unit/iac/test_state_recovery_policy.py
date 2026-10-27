from __future__ import annotations

from itertools import product

import pytest

from scripts.iac.state_recovery_policy import recovery_decision


@pytest.mark.parametrize(
    ("interrupted", "lock", "alive", "changed", "approved"),
    list(product([False, True], [False, True], [False, True, None], [False, True], [False, True])),
)
def test_recovery_never_unlocks_deletes_or_resumes(
    interrupted: bool, lock: bool, alive: bool | None, changed: bool, approved: bool
) -> None:
    result = recovery_decision(
        interrupted=interrupted,
        lock_present=lock,
        owner_alive=alive,
        state_changed=changed,
        approval_current=approved,
    )
    assert not result["automatic_force_unlock"] and not result["delete_state"]
    assert not result["resume_old_request"] and not result["production_apply_enabled"]
    assert result["new_verification_required"]
    if interrupted or lock or alive is not False or changed or not approved:
        assert result["decision"] == "MANUAL_REVIEW"
    else:
        assert result["decision"] == "NEW_REQUEST_REQUIRED"


def test_recovery_rejects_unknown_or_truthy_observations() -> None:
    with pytest.raises(ValueError):
        recovery_decision(
            interrupted=False,
            lock_present=False,
            owner_alive=1,  # type: ignore[arg-type]
            state_changed=False,
            approval_current=True,
        )
