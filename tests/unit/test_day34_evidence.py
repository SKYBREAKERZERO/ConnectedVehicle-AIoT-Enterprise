"""Gate fixtures exercise rejection; they are never integration acceptance evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from scripts import day34_evidence as gate
from scripts.day18_evidence import REQUIRED as EXECUTION_CHECKS
from scripts.day19_evidence import REQUIRED as CAMPAIGN_CHECKS


@pytest.mark.parametrize(
    "fault",
    ["none", "missing", "failed", "skip", "commit", "run", "stale", "log", "quality", "truthy"],
)
def test_day34_gate_denies_incomplete_or_mixed_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("PIPELINE_NEEDS", raising=False)
    expected = {"commit": "a" * 40, "run_id": "test:1", "source_sha256": "b" * 64}
    bound = expected | {"day34_source_sha256": "c" * 64}
    monkeypatch.setattr(gate, "provenance", lambda: expected)
    monkeypatch.setattr(gate, "binding", lambda: bound)
    for name, required in (
        ("day18-ota-execution.json", EXECUTION_CHECKS),
        ("day19-campaign.json", CAMPAIGN_CHECKS),
    ):
        record: dict[str, Any] = dict(
            version=1,
            profile="local_drill",
            provenance=dict(expected),
            generated_at_utc=datetime.now(UTC).isoformat(),
            checks=dict.fromkeys(required, True),
            simulated_installation=True,
            physical_boot_verified=False,
            real_aws_verified=False,
        )
        if name.startswith("day19"):
            if fault == "missing":
                record["checks"].pop(next(iter(required)))
            elif fault in {"failed", "truthy"}:
                record["checks"][next(iter(required))] = 1 if fault == "truthy" else False
            elif fault in {"commit", "run"}:
                record["provenance"]["commit" if fault == "commit" else "run_id"] = "other"
            elif fault == "stale":
                record["generated_at_utc"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        gate.write(tmp_path / name, record)
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    properties = ET.SubElement(suite, "properties")
    for key, value in bound.items():
        ET.SubElement(properties, "property", name=key, value=value)
    for name in gate.POSTGRES_CASES:
        case = ET.SubElement(suite, "testcase", name=name)
        if fault == "skip":
            ET.SubElement(case, "skipped")
    (tmp_path / "day21-postgres.xml").write_bytes(ET.tostring(root))
    checks = {}
    for name in gate.COMMANDS:
        log = b"executed fixture log"
        (tmp_path / f"day34-{name}.log").write_bytes(log)
        checks[name] = dict(
            exit_code=1 if fault == "quality" else 0, log_sha256=hashlib.sha256(log).hexdigest()
        )
    gate.write(
        tmp_path / "day34-quality.json",
        dict(
            provenance=bound,
            checks=checks,
            generated_at_utc=datetime.now(UTC).isoformat(),
        ),
    )
    if fault == "log":
        (tmp_path / "day34-mypy.log").write_text("altered", encoding="utf-8")
    if fault == "none":
        result = gate.evaluate(tmp_path)
        assert result["decision"] == "READY_FOR_LOCAL_REVIEW"
        assert result["release_authorized"] is False
    else:
        with pytest.raises(ValueError):
            gate.evaluate(tmp_path)


def test_day34_missing_files_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("PIPELINE_NEEDS", raising=False)
    monkeypatch.setenv("DAY16_EVIDENCE_RUN_ID", "unit-only")
    with pytest.raises(FileNotFoundError):
        gate.evaluate(tmp_path)


@pytest.mark.parametrize("result", ["missing", "failure", "cancelled", "skipped"])
def test_day34_ci_requires_successful_native_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: str
) -> None:
    monkeypatch.setattr(gate, "binding", lambda: {})
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    if result == "missing":
        monkeypatch.delenv("PIPELINE_NEEDS", raising=False)
    else:
        needs = dict.fromkeys(
            ["baseline", "lint", "types", "contracts", "integration", "postgres", "observability"],
            {"result": "success"},
        )
        needs["postgres"] = {"result": result}
        monkeypatch.setenv("PIPELINE_NEEDS", json.dumps(needs))
    with pytest.raises(ValueError):
        gate.evaluate(tmp_path)
