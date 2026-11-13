"""Classify release outcomes from a complete, ordered execution history."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum


class Outcome(StrEnum):
    BLOCKED = "BLOCKED"
    CANARY_PASSED = "CANARY_PASSED"
    RELEASE_ACCEPTED = "RELEASE_ACCEPTED"
    FAILED_RECOVERED = "FAILED_RECOVERED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


def classify(events: Sequence[str], wave_count: int) -> Outcome:
    if wave_count < 1 or not events or events[0] != "ADMITTED":
        return Outcome.BLOCKED
    tail = list(events[1:])
    passed = 0
    while tail and tail[0] == f"WAVE_PASSED:{passed + 1}" and passed < wave_count:
        tail.pop(0)
        passed += 1
    if tail and tail[0] in {"ECS_FAILED", "OTA_FAILED"}:
        mitigation = "ECS_REVERTED" if tail[0] == "ECS_FAILED" else "CAMPAIGN_PAUSED"
        if tail == [tail[0], "EXPANSION_STOPPED", mitigation, "RECONCILED"]:
            return Outcome.FAILED_RECOVERED
        return Outcome.RECOVERY_REQUIRED
    if passed == wave_count and tail == ["FINAL_VERIFIED"]:
        return Outcome.RELEASE_ACCEPTED
    if passed and not tail:
        return Outcome.CANARY_PASSED
    return Outcome.BLOCKED
