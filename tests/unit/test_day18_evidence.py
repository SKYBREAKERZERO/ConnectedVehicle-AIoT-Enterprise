from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.day16_evidence import provenance
from scripts.day17_release import evaluate as base_evaluate
from scripts.day17_release import read_json, write_json
from scripts.day18_evidence import REQUIRED, evaluate, source_digest, verify
from tests.unit.test_day17_release_bundle import bundle


def seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle(tmp_path, monkeypatch)
    write_json(tmp_path / "day17-readiness.json", base_evaluate(tmp_path))
    write_json(
        tmp_path / "day18-ota-execution.json",
        dict(
            version=1,
            profile="local_drill",
            provenance=provenance(),
            day18_sha256=source_digest(),
            checks={key: True for key in sorted(REQUIRED)},
            generated_at_utc=datetime.now(UTC).isoformat(),
            real_aws_verified=False,
            simulated_installation=True,
            physical_boot_verified=False,
            device_installations=1,
            cloud_security_version=1,
            device_security_version=1,
            pending_reports=0,
        ),
    )


def test_day18_gate_recomputes_immutable_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed(tmp_path, monkeypatch)
    expected = evaluate(tmp_path)
    write_json(tmp_path / "day18-acceptance.json", expected)
    assert verify(tmp_path) == expected
    with pytest.raises(FileExistsError):
        write_json(tmp_path / "day18-acceptance.json", expected)


@pytest.mark.parametrize(
    "case",
    ["source", "missing", "failed", "counter", "pending", "stale", "future", "aws", "physical"],
)
def test_day18_gate_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    seed(tmp_path, monkeypatch)
    path = tmp_path / "day18-ota-execution.json"
    report = read_json(path)
    if case == "source":
        report["day18_sha256"] = "0" * 64
    elif case == "missing":
        report["checks"].pop(next(iter(REQUIRED)))
    elif case == "failed":
        report["checks"][next(iter(REQUIRED))] = False
    elif case == "counter":
        report["cloud_security_version"] = 2
    elif case == "pending":
        report["pending_reports"] = 1
    elif case in {"stale", "future"}:
        report["generated_at_utc"] = (
            datetime.now(UTC) + timedelta(seconds=901 if case == "future" else -901)
        ).isoformat()
    elif case == "aws":
        report["real_aws_verified"] = True
    else:
        report["simulated_installation"] = False
    import json

    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        evaluate(tmp_path)
