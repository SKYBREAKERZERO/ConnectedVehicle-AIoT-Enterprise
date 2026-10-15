from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.day16_evidence import REQUIRED, SCENARIOS, evidence, verify


def seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNTIME_EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("DAY16_EVIDENCE_RUN_ID", "unit-fixture")
    for scenario in SCENARIOS:
        evidence(scenario, dict.fromkeys(REQUIRED[scenario], True))


def test_complete_evidence_and_exclusive_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed(tmp_path, monkeypatch)
    assert json.loads(verify(tmp_path).read_text())["status"] == "passed"
    with pytest.raises(FileExistsError):
        verify(tmp_path)


@pytest.mark.parametrize("case", ["missing", "false", "run", "source", "aws", "empty"])
def test_gate_rejects_invalid_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    seed(tmp_path, monkeypatch)
    path = tmp_path / "day16-commit-unknown.json"
    record = json.loads(path.read_text())
    if case == "missing":
        path.unlink()
    else:
        if case == "false":
            record["checks"]["durable_result_reconciled"] = False
        elif case == "empty":
            record["checks"] = {}
        elif case == "aws":
            record["real_aws_verified"] = True
        else:
            record["provenance"]["run_id" if case == "run" else "source_sha256"] = "stale"
        path.write_text(json.dumps(record))
    with pytest.raises((ValueError, FileNotFoundError)):
        verify(tmp_path)
    assert not (tmp_path / "day16-acceptance.json").exists()


def test_evidence_rejects_overwrite_and_failed_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed(tmp_path, monkeypatch)
    with pytest.raises(FileExistsError):
        evidence("commit-unknown", dict.fromkeys(REQUIRED["commit-unknown"], True))
    with pytest.raises(ValueError):
        evidence("commit-unknown", {"assertion": False})
