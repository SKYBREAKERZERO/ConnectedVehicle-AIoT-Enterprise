"""F11 and source/attempt integrity of mandatory twelve-flow proof."""

from __future__ import annotations

import json
from collections.abc import Callable
from xml.etree import ElementTree as ET

import pytest

from scripts.iac.day31_evidence import provenance, verify_documents
from tests.unit.iac.test_workflow_evidence_binding import documents


@pytest.fixture(scope="module", autouse=True)
def stamp(record_testsuite_property: Callable[[str, object], None]) -> None:
    for k, v in provenance().items():
        record_testsuite_property(k, v)


def test_day31_complete_documents_are_not_a_release_authorization() -> None:
    unit, fault, facts, p = documents()
    assert verify_documents(unit, fault, facts, p)["apply_authorized"] is False


@pytest.mark.parametrize("flow", ["F11", "source", "attempt", "skipped", "tamper"])
def test_day31_evidence_refuses_missing_and_replayed_flow_proof(flow: str) -> None:
    unit, fault, facts, p = documents()
    if flow == "F11":
        root = ET.fromstring(fault)
        suite = root.find("testsuite")
        assert suite is not None
        suite.remove(suite[-1])
        fault = ET.tostring(root)
    if flow == "source":
        p = {**p, "day31_source_sha256": "f" * 64}
    if flow == "attempt":
        p = {**p, "day31_run_id": "10:2"}
    if flow == "skipped":
        root = ET.fromstring(fault)
        ET.SubElement(root.findall(".//testcase")[0], "skipped")
        fault = ET.tostring(root)
    if flow == "tamper":
        value = json.loads(facts)
        value["lock_consumptions"] = 2
        facts = json.dumps(value).encode()
    with pytest.raises(ValueError):
        verify_documents(unit, fault, facts, p)


def test_trusted_aggregator_keeps_pr_execution_and_token_scope_separate() -> None:
    from scripts.iac.day31_evidence import ROOT

    workflow = (ROOT / ".github/workflows/day31-trust-boundary.yml").read_text(encoding="utf-8-sig")
    trusted = workflow.split("  trusted-readonly-binding:", 1)[1]
    assert "ref: ${{ github.workflow_sha }}" in trusted
    assert "actions: read" in trusted and "pull-requests: read" in trusted
    assert not any(
        bad in trusted
        for bad in (": write", "workflow_run.head_sha", "pip install", "download-artifact")
    )
    assert "pull_request_target" not in workflow


def test_uninstalled_control_plane_is_not_qualified_by_local_audit(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    from scripts.iac import workflow_evidence_binding as m

    output = Path(str(tmp_path)) / "binding.json"
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(m, "GitHub", lambda: object())
    monkeypatch.setattr(
        m,
        "live",
        lambda *a: {
            "trusted_control_plane_installed": False,
            "apply_authorized": False,
            "release_authorized": False,
        },
    )
    monkeypatch.setattr("sys.argv", ["binder", "--pr", "15", "--output", str(output)])
    with pytest.raises(ValueError, match="not installed"):
        m.main()
    monkeypatch.setattr(
        "sys.argv", ["binder", "--pr", "15", "--output", str(output), "--inspect-uninstalled"]
    )
    m.main()
    report = json.loads(output.read_text())
    assert (
        report["verification_mode"] == "local-readonly-api-inspection"
        and report["release_authorized"] is False
    )
