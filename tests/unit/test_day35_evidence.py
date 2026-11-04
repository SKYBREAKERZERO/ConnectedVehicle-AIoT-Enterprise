"""Controlled verifier fixtures never count as real PostgreSQL acceptance."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from scripts import day34_evidence
from scripts import day35_evidence as gate


def prepared(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    expected = {
        "commit": "a" * 40,
        "run_id": "123:2",
        "source_sha256": "b" * 64,
        "day34_source_sha256": "c" * 64,
    }
    monkeypatch.setattr(day34_evidence, "binding", lambda: expected)
    prior = {"decision": "READY_FOR_LOCAL_REVIEW", "ci_verified": True, "release_authorized": False}
    monkeypatch.setattr(day34_evidence, "evaluate", lambda _: prior)
    (tmp / "day34-acceptance.json").write_text(json.dumps(prior))
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    props = ET.SubElement(suite, "properties")
    for k, v in expected.items():
        ET.SubElement(props, "property", name=k, value=v)
    for name in sorted(gate.REQUIRED):
        ET.SubElement(suite, "testcase", name=name)
    (tmp / "day35-runtime-faults.xml").write_bytes(ET.tostring(root))
    return expected


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "missing",
        "skip",
        "failed",
        "missing_case",
        "duplicate",
        "run",
        "source",
        "prior",
        "hash",
        "stale",
        "github_attempt",
    ],
)
def test_day35_refuses_incomplete_replayed_or_modified_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    expected = prepared(tmp_path, monkeypatch)
    folder = tmp_path
    path = folder / "day35-runtime-faults.xml"
    tree = ET.fromstring(path.read_bytes())
    suite = tree.find("testsuite")
    assert suite is not None
    if fault == "missing":
        path.unlink()
    elif fault in {"skip", "failed"}:
        case = suite.find("testcase")
        assert case is not None
        ET.SubElement(case, "skipped" if fault == "skip" else "failure")
        path.write_bytes(ET.tostring(tree))
    elif fault == "missing_case":
        case = suite.find("testcase")
        assert case is not None
        suite.remove(case)
        path.write_bytes(ET.tostring(tree))
    elif fault == "duplicate":
        ET.SubElement(suite, "testcase", name=next(iter(gate.REQUIRED)))
        path.write_bytes(ET.tostring(tree))
    elif fault in {"run", "source"}:
        for prop in tree.findall(".//property"):
            if prop.get("name") == ("run_id" if fault == "run" else "source_sha256"):
                prop.set("value", "other")
        path.write_bytes(ET.tostring(tree))
    elif fault == "prior":
        (folder / "day34-acceptance.json").write_text("{}")
    elif fault == "github_attempt":
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_SHA", expected["commit"])
        monkeypatch.setenv("GITHUB_RUN_ID", "123")
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    if fault in {"hash", "stale"}:
        record: dict[str, Any] = gate.evaluate(folder)
        record["generated_at_utc"] = (
            datetime.now(UTC) - timedelta(hours=2) if fault == "stale" else datetime.now(UTC)
        ).isoformat()
        (folder / "day35-acceptance.json").write_text(json.dumps(record))
        if fault == "hash":
            path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(ValueError):
            gate.check_existing(folder)
    elif fault == "none":
        result = gate.evaluate(folder)
        assert result["decision"] == "READY_FOR_LOCAL_REVIEW"
        assert (
            result["real_aws_verified"]
            is result["physical_boot_verified"]
            is result["release_authorized"]
            is False
        )
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            gate.evaluate(folder)


def test_day35_cli_malformed_xml_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prepared(tmp_path, monkeypatch)
    (tmp_path / "day35-runtime-faults.xml").write_text("<bad")
    monkeypatch.setattr("sys.argv", ["day35", "--directory", str(tmp_path)])
    assert gate.main() == 1
    assert json.loads((tmp_path / "day35-acceptance.json").read_text())["decision"] == "BLOCKED"


@pytest.mark.parametrize("fault", ["none", "missing", "run", "commit", "hash", "release", "ci"])
def test_day35_actual_final_workflow_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    import hashlib
    import os
    import subprocess
    import sys

    from tests.unit.iac.test_workflow import read

    workflow = read(".github/workflows/runtime.yml")
    step = next(
        s
        for s in workflow["jobs"]["runtime"]["steps"]
        if s.get("name") == "Require Day35 acceptance from this candidate and attempt"
    )
    code = "\n".join(step["run"].strip().splitlines()[1:-1])
    folder = tmp_path / ".ci-inputs/runtime-evidence"
    folder.mkdir(parents=True)
    for name in ["day35-runtime-faults.xml", "day34-acceptance.json"]:
        (folder / name).write_bytes(b"checked-by-producer")
    record: dict[str, Any] = dict(
        decision="READY_FOR_LOCAL_REVIEW",
        ci_verified=True,
        release_authorized=False,
        real_aws_verified=False,
        physical_boot_verified=False,
        provenance=dict(commit="a" * 40, run_id="123:2"),
        proofs={
            n: hashlib.sha256((folder / n).read_bytes()).hexdigest()
            for n in ["day35-runtime-faults.xml", "day34-acceptance.json"]
        },
    )
    if fault in {"run", "commit"}:
        record["provenance"]["run_id" if fault == "run" else "commit"] = "other"
    elif fault in {"release", "ci"}:
        record["release_authorized" if fault == "release" else "ci_verified"] = fault == "release"
    elif fault == "hash":
        (folder / "day35-runtime-faults.xml").write_bytes(b"changed")
    if fault != "missing":
        (folder / "day35-acceptance.json").write_text(json.dumps(record))
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
        env=dict(os.environ, GITHUB_SHA="a" * 40, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2"),
    )
    assert (result.returncode == 0) is (fault == "none"), result.stderr.decode()


def test_day35_workflow_keeps_upstream_identity_and_real_faults() -> None:
    from tests.unit.iac.test_workflow import read

    workflow = read(".github/workflows/runtime.yml")
    steps = workflow["jobs"]["evidence"]["steps"]
    admission = next(s for s in steps if s.get("name") == "Day35 fault and evidence admission")
    assert admission["env"]["PIPELINE_NEEDS"] == "${{ toJSON(needs) }}"
    assert "scripts.day35_evidence --check-existing" in admission["run"]
    assert steps.index(admission) < next(
        i
        for i, s in enumerate(steps)
        if "--stage runtime-evidence --folder" in s.get("run", "") and "publish" in s.get("run", "")
    )
    pg = read(".github/workflows/runtime-postgres.yml")
    faults = next(
        s for s in pg["jobs"]["run"]["steps"] if "tests/integration/day35" in s.get("run", "")
    )
    assert faults["if"] == "inputs.suite == 'postgres'"
    assert "--junitxml=.runtime-reports/day35-runtime-faults.xml" in faults["run"]
