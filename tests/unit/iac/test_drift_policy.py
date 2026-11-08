from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.iac.drift_policy import drift_report, reconciliation_errors
from tests.unit.iac.test_state_integrity import sample


def plan() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.7",
        "complete": True,
        "resource_changes": [],
        "resource_drift": [],
        "output_changes": {},
    }


def change() -> dict[str, Any]:
    return {"address": "aws_s3_bucket_versioning.fixture", "change": {"actions": ["update"]}}


def test_clean_and_two_distinct_drift_classes() -> None:
    assert drift_report(0, plan(), 0, plan())["decision"] == "CLEAR"
    refresh = plan()
    refresh["resource_drift"] = [change()]
    state = drift_report(2, refresh, 0, plan())
    assert state["state_drift"] and not state["configuration_drift"]
    normal = plan()
    normal["resource_changes"] = [change()]
    config = drift_report(0, plan(), 2, normal)
    assert config["configuration_drift"] and not config["state_drift"]
    for result in (state, config):
        assert (
            result["decision"] == "REVIEW_REQUIRED"
            and not result["automatic_remediation"]
            and result["new_review_required"]
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "exit1",
        "unexpected-exit",
        "bool-exit",
        "incomplete",
        "deferred",
        "errored",
        "format",
        "code-contradiction",
        "malformed",
        "unknown-action",
    ],
)
def test_failed_or_inconsistent_plans_fail_closed(mutation: str) -> None:
    refresh, normal = plan(), plan()
    code = 0
    if mutation == "exit1":
        code = 1
    if mutation == "unexpected-exit":
        code = 3
    if mutation == "bool-exit":
        code = False
    if mutation == "incomplete":
        refresh["complete"] = False
    if mutation == "deferred":
        refresh["deferred_changes"] = [{}]
    if mutation == "errored":
        refresh["errored"] = True
    if mutation == "format":
        refresh["format_version"] = "unsupported"
    if mutation == "code-contradiction":
        refresh["resource_drift"] = [change()]
    if mutation == "malformed":
        refresh["resource_changes"] = {}
    if mutation == "unknown-action":
        refresh["resource_changes"] = [{"change": {"actions": ["execute"]}}]
    assert drift_report(code, refresh, 0, normal)["decision"] == "ERROR"


def test_refresh_only_cannot_clear_a_configuration_plan_difference() -> None:
    normal = plan()
    normal["resource_changes"] = [change()]
    assert drift_report(0, plan(), 2, normal)["decision"] == "REVIEW_REQUIRED"


def reconciliation() -> dict[str, Any]:
    _, state = sample()
    expected = {**state, "resource_id": "fixture-bucket", "resource_fingerprint": "c" * 64}
    return {
        "release": {**expected, "status": "VERIFIED"},
        "expected": expected,
        "state": state,
        "resource": {"resource_id": "fixture-bucket", "resource_fingerprint": "c" * 64},
        "drift": drift_report(0, plan(), 0, plan()),
        "authenticate": lambda _: True,
    }


def test_matching_release_state_and_actual_resource_reconcile_for_review() -> None:
    assert reconciliation_errors(**reconciliation()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "interrupted",
        "ready-reuse",
        "old-run",
        "wrong-source",
        "state",
        "version",
        "actual-resource",
        "drift",
        "authority",
    ],
)
def test_reconciliation_blocks_ambiguous_or_stale_releases(mutation: str) -> None:
    args = deepcopy(reconciliation())
    if mutation == "interrupted":
        args["release"]["status"] = "INTERRUPTED"
    if mutation == "ready-reuse":
        args["release"]["status"] = "READY"
    if mutation == "old-run":
        args["release"]["run_id"] = "99999:1"
    if mutation == "wrong-source":
        args["release"]["commit"] = "b" * 40
    if mutation == "state":
        args["state"]["serial"] -= 1
    if mutation == "version":
        args["state"]["version_id"] = "old-version"
    if mutation == "actual-resource":
        args["resource"]["resource_fingerprint"] = "e" * 64
    if mutation == "drift":
        args["drift"]["decision"] = "REVIEW_REQUIRED"
    if mutation == "authority":
        args["authenticate"] = lambda _: False
    assert reconciliation_errors(**args)


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "unit-case",
        "unit-run",
        "dr-source",
        "dr-failure",
        "dr-duplicate",
        "unsafe-restore",
        "state-hash",
        "same-backend",
        "old-state-run",
        "empty-report",
        "missing-version",
        "missing-plan-digest",
    ],
)
def test_day28_evidence_rejects_missing_failed_or_relabelled_proofs(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    import json
    from xml.etree import ElementTree

    from scripts.iac import day28_evidence as module

    _, record = sample()
    monkeypatch.setattr(
        module,
        "day27_evidence",
        lambda _: {
            "provenance": {"day27_commit": record["commit"], "day27_run_id": record["run_id"]}
        },
    )
    expected = {
        "day28_commit": record["commit"],
        "day28_run_id": record["run_id"],
        "day28_source_sha256": module.source_digest(),
    }

    def xml(name: str, cases: list[str]) -> tuple[Any, Any, Any, Any]:
        doc = ElementTree.Element("testsuites")
        suite = ElementTree.SubElement(doc, "testsuite")
        props = ElementTree.SubElement(suite, "properties")
        for key, value in expected.items():
            ElementTree.SubElement(props, "property", name=key, value=value)
        for case in cases:
            ElementTree.SubElement(suite, "testcase", name=case)
        return doc, suite, props, tmp_path / name

    unit, suite, unit_props, unit_path = xml("unit.xml", list(module.SCENARIOS))
    dr, dr_suite, dr_props, dr_path = xml(
        "dr.xml", ["test_versioned_state_recovery_and_both_drift_plans"]
    )
    result: dict[str, Any] = {
        "provenance": expected,
        "status": "passed",
        "scope": "localstack-only",
        "corrupt_state_denied": True,
        "missing_state_denied": True,
        "pinned_version_restored_to_isolated_copy": True,
        "read_only_plans_preserved_state": True,
        "resource_drift_not_repaired": True,
        "interrupted_release_denied": True,
        "new_request_and_approval_required": True,
        "aws_verified": False,
        "production_apply_enabled": False,
        "automatic_restore_active_backend": False,
        "automatic_force_unlock": False,
        "independent_human_approval_exercised": False,
        "state_record": record,
        "recovered_state_record": {
            **record,
            "bucket": "cv-isolated-copy",
            "version_id": "new-version",
        },
    }
    for name, code, decision in (
        ("baseline", 0, "CLEAR"),
        ("injected_drift", 2, "REVIEW_REQUIRED"),
        ("post_restore", 2, "REVIEW_REQUIRED"),
    ):
        result[name] = {
            "plan_sha256": {"refresh": "d" * 64, "normal": "e" * 64},
            "refresh_exit": code,
            "normal_exit": code,
            "classification": {
                "decision": decision,
                "state_drift": code == 2,
                "configuration_drift": code == 2,
                "automatic_remediation": False,
                "production_apply_enabled": False,
                "new_review_required": True,
            },
        }
    if mutation == "unit-case":
        suite.remove(suite[-1])
    if mutation == "unit-run":
        unit_props[1].set("value", "999:1")
    if mutation == "dr-source":
        dr_props[2].set("value", "f" * 64)
    if mutation == "dr-failure":
        ElementTree.SubElement(dr_suite[-1], "failure")
    if mutation == "dr-duplicate":
        ElementTree.SubElement(
            dr_suite, "testcase", name="test_versioned_state_recovery_and_both_drift_plans"
        )
    if mutation == "unsafe-restore":
        result["automatic_restore_active_backend"] = True
    if mutation == "state-hash":
        result["recovered_state_record"]["sha256"] = "f" * 64
    if mutation == "same-backend":
        result["recovered_state_record"]["bucket"] = record["bucket"]
    if mutation == "old-state-run":
        result["state_record"]["run_id"] = "99999:1"
    if mutation == "empty-report":
        result = {}
    if mutation == "missing-version":
        del result["recovered_state_record"]["version_id"]
    if mutation == "missing-plan-digest":
        del result["baseline"]["plan_sha256"]
    ElementTree.ElementTree(unit).write(unit_path)
    ElementTree.ElementTree(dr).write(dr_path)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(result), encoding="utf-8")
    if mutation == "none":
        assert module.evidence(unit_path, dr_path, path)["deployment_admitted"] is False
    else:
        with pytest.raises(ValueError):
            module.evidence(unit_path, dr_path, path)
