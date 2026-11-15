"""Read-only recovery advice. Never issue an unlock, state delete, restore or Apply."""

from __future__ import annotations

from typing import Any


def recovery_decision(
    *,
    interrupted: bool,
    lock_present: bool,
    owner_alive: bool | None,
    state_changed: bool,
    approval_current: bool,
) -> dict[str, Any]:
    if not all(
        type(value) is bool
        for value in (interrupted, lock_present, state_changed, approval_current)
    ) or (owner_alive is not None and type(owner_alive) is not bool):
        raise ValueError("explicit trusted observations required")
    reasons = []
    if interrupted:
        reasons.append("execution interrupted; outcome may be ambiguous")
    if lock_present:
        reasons.append("lock ownership must be reconciled by an authorized operator")
    if owner_alive is not False:
        reasons.append("original executor may still be active")
    if state_changed:
        reasons.append("state changed; re-plan and fresh review required")
    if not approval_current:
        reasons.append("approval absent, expired or revoked")
    return {
        "decision": "MANUAL_REVIEW" if reasons else "NEW_REQUEST_REQUIRED",
        "reasons": reasons,
        "automatic_force_unlock": False,
        "delete_state": False,
        "resume_old_request": False,
        "new_verification_required": True,
        "production_apply_enabled": False,
    }
