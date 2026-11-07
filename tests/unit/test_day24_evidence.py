from __future__ import annotations

import hashlib
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scripts.day16_evidence import source_digest
from scripts.day24_evidence import REQUIRED, ROOT, evaluate


def report(directory: Path, *, failure: str = "", omit: bool = False) -> None:
    names = sorted(REQUIRED)
    if omit:
        names.pop()
    cases = "".join(f'<testcase name="{name}">{failure}</testcase>' for name in names)
    stamp = {
        "day24_commit": "a" * 40,
        "day24_run_id": "42:1",
        "day24_source_sha256": source_digest(),
        "day24_rule_sha256": hashlib.sha256(
            (ROOT / "infra/observability/day24-campaign.yml").read_bytes()
        ).hexdigest(),
        "day24_scenario_sha256": hashlib.sha256(
            (ROOT / "tests/fixtures/day24/alerts.test.yml").read_bytes()
        ).hexdigest(),
    }
    properties = (
        "<properties>"
        + "".join(f'<property name="{key}" value="{value}"/>' for key, value in stamp.items())
        + "</properties>"
    )
    (directory / "day24-postgres-alerts.xml").write_text(
        f"<testsuites><testsuite>{properties}{cases}</testsuite></testsuites>", encoding="utf-8"
    )


def test_complete_report_is_bound_to_source_and_run(tmp_path: Path) -> None:
    report(tmp_path)
    result = evaluate(tmp_path, commit="a" * 40, run_id="42:1")
    assert result["provenance"]["commit"] == "a" * 40
    assert result["provenance"]["run_id"] == "42:1"
    assert result["real_aws_verified"] is False
    assert result["live_alert_delivery_verified"] is False
    assert len(result["tests"]) == 8


@pytest.mark.parametrize("tag", ("failure", "error", "skipped"))
def test_failed_or_skipped_scenarios_fail_closed(tmp_path: Path, tag: str) -> None:
    report(tmp_path, failure=f"<{tag}/>")
    with pytest.raises(ValueError, match="Failed or skipped"):
        evaluate(tmp_path, commit="a" * 40, run_id="42:1")


def test_missing_scenario_fails_closed(tmp_path: Path) -> None:
    report(tmp_path, omit=True)
    with pytest.raises(ValueError, match="Missing or duplicate"):
        evaluate(tmp_path, commit="a" * 40, run_id="42:1")


@pytest.mark.parametrize("commit,run_id", (("bad", "42:1"), ("a" * 40, "")))
def test_provenance_is_required(tmp_path: Path, commit: str, run_id: str) -> None:
    report(tmp_path)
    with pytest.raises(ValueError, match="explicit source"):
        evaluate(tmp_path, commit=commit, run_id=run_id)


@pytest.mark.parametrize("commit,run_id", (("b" * 40, "42:1"), ("a" * 40, "43:1")))
def test_cached_xml_cannot_be_relabelled_as_new_source_or_run(
    tmp_path: Path, commit: str, run_id: str
) -> None:
    report(tmp_path)
    with pytest.raises(ValueError, match="test-time provenance"):
        evaluate(tmp_path, commit=commit, run_id=run_id)


@pytest.mark.parametrize("violation", ("missing_stamp", "direct_cases", "duplicate_stamp", "root"))
def test_ambiguous_xml_cannot_bypass_test_time_attestation(tmp_path: Path, violation: str) -> None:
    report(tmp_path)
    path = tmp_path / "day24-postgres-alerts.xml"
    document = ElementTree.fromstring(path.read_bytes())
    suite = document.find("testsuite")
    assert suite is not None
    properties = suite.find("properties")
    assert properties is not None
    if violation == "missing_stamp":
        suite.remove(properties)
    elif violation == "direct_cases":
        document.remove(suite)
        document.extend(suite.findall("testcase"))
    elif violation == "duplicate_stamp":
        properties.append(properties[0])
    else:
        document.tag = "unknown"
    path.write_bytes(ElementTree.tostring(document))
    with pytest.raises(ValueError):
        evaluate(tmp_path, commit="a" * 40, run_id="42:1")
