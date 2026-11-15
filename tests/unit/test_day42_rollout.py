import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from scripts.day42_recovery import Outcome, classify
from scripts.day42_release_admission import Release

SPEC = Path("infra/step-functions/day42-rollout.asl.json")


def simulate(responses: dict[str, list[str]]) -> str:
    """Execute the supported ASL subset with scripted adapter responses."""
    definition = json.loads(SPEC.read_text(encoding="utf-8"))
    state = definition["StartAt"]
    status = ""
    wave = 1
    for _ in range(200):
        step = definition["States"][state]
        if step.get("End"):
            assert all(not values for values in responses.values())
            return str(step["Result"]["status"])
        if step["Type"] == "Task":
            assert "Retry" not in step
            status = responses[step["Parameters"]["operation"]].pop(0)
            state = step["Catch"][0]["Next"] if status == "ERROR" else step["Next"]
        elif step["Type"] == "Choice":
            rules: list[dict[str, Any]] = step["Choices"]
            state = next(
                (
                    rule["Next"]
                    for rule in rules
                    if rule.get("StringEquals") == status
                    or ("NumericLessThanEquals" in rule and wave <= rule["NumericLessThanEquals"])
                ),
                step["Default"],
            )
        else:
            if state == "AdvanceWave":
                wave += 1
            state = step["Next"]
    raise AssertionError("Unbounded state machine")


def test_approval_binds_exact_release_and_stable_execution() -> None:
    approved = Release(
        "a" * 40, "sha256:" + "b" * 64, "approval-123456789", "123456789012", "cv", "ota"
    )
    assert approved.execution_identity(approved) == replace(approved).execution_identity(approved)
    with pytest.raises(ValueError, match="trusted approval"):
        replace(approved, campaign="other").execution_identity(approved)


def test_success_requires_all_waves_and_final_evidence() -> None:
    assert (
        simulate(
            {
                "admit": ["ADMITTED"],
                "open_wave": ["OPENED", "OPENED"],
                "observe_wave": ["CANARY_PASSED", "ALL_WAVES_PASSED"],
                "verify_final": ["VERIFIED"],
            }
        )
        == Outcome.RELEASE_ACCEPTED
    )
    assert classify(["ADMITTED", "WAVE_PASSED:1"], 2) == Outcome.CANARY_PASSED
    assert classify(["ADMITTED", "WAVE_PASSED:2", "FINAL_VERIFIED"], 2) == Outcome.BLOCKED


def test_ota_timeout_pauses_without_reverting_firmware() -> None:
    assert (
        simulate(
            {
                "admit": ["ADMITTED"],
                "open_wave": ["OPENED"],
                "observe_wave": ["ERROR"],
                "stop_expansion": ["OTA_PAUSED"],
                "reconcile": ["RECONCILED"],
            }
        )
        == Outcome.FAILED_RECOVERED
    )
    assert (
        classify(["ADMITTED", "OTA_FAILED", "EXPANSION_STOPPED", "ECS_REVERTED", "RECONCILED"], 1)
        == Outcome.RECOVERY_REQUIRED
    )


def test_ecs_rollback_failure_requires_intervention() -> None:
    assert (
        simulate(
            {
                "admit": ["ADMITTED"],
                "open_wave": ["OPENED"],
                "observe_wave": ["FAILED"],
                "stop_expansion": ["ECS_STOPPED"],
                "revert_verified_ecs": ["ERROR"],
            }
        )
        == Outcome.RECOVERY_REQUIRED
    )


def test_approval_unavailable_never_opens_wave() -> None:
    assert simulate({"admit": ["ERROR"]}) == Outcome.BLOCKED
