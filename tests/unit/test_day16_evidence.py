from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from database.credential_audit import encoded
from scripts.day16_evidence import REQUIRED, SCENARIOS, evidence, provenance, verify, write_record


def demo_proof() -> dict[str, object]:
    segments = []
    previous = None
    for index in range(2):
        record = dict(
            operation_id="a" * 32,
            offset=index,
            previous_sha256=previous,
            events=[
                dict(
                    sequence=index + 1,
                    time="2026-10-15T00:00:00+00:00",
                    phase="complete",
                    action="state",
                    retirement_status=None,
                    failure_type=None,
                )
            ],
        )
        previous = hashlib.sha256(encoded(record)).hexdigest()
        segments.append(dict(sha256=previous, record=record))
    archives = {str(index): row["sha256"] for index, row in enumerate(segments)}
    cases = []
    for name in ("lock", "worker"):
        events = [
            dict(
                sequence=index,
                state=state,
                operation_id="a" * 32,
                fault_id="b" * 32,
                request_id="request",
                correlation_id="correlation",
                trace_id="c" * 32,
                component="database" if name == "lock" else "worker",
                sqlstate="55P03" if state == "FAULT_DETECTED" else None,
            )
            for index, state in enumerate(
                ("RUNNING", "FAULT_DETECTED", "CLASSIFIED", "RETRY", "VERIFY", "RECOVERED"), 1
            )
        ]
        cases.append(
            dict(
                case=name,
                operation_id="a" * 32,
                fault_id="b" * 32,
                elapsed_seconds=1,
                events=events,
                prometheus_samples=[
                    {"state": state, "value": 1}
                    for state in ("FAULT_DETECTED", "RETRY", "RECOVERED")
                ],
                after={
                    "status": "requested" if name == "lock" else "succeeded",
                    "outbox": 1,
                    "reports": 0 if name == "lock" else 2,
                },
                device_executions=1,
                device_locked=1,
            )
        )
    return dict(
        version=1,
        real_aws_verified=False,
        provenance=provenance(),
        cases=cases,
        audit=dict(
            phase_before="complete",
            phase_after="complete",
            sequence_before=2,
            sequence_after=3,
            archives_before=archives,
            archives_after=dict(archives),
            checkpoint_unchanged_on_failure=True,
            chain_verified=True,
            segments=segments,
            checkpoint=dict(
                operation_id="a" * 32,
                phase="complete",
                audit_offset=2,
                audit_archive_sha256=previous,
                events=[
                    dict(
                        sequence=3,
                        time="2026-10-15T00:00:00+00:00",
                        phase="complete",
                        action="state",
                        retirement_status=None,
                        failure_type=None,
                    )
                ],
            ),
        ),
    )


def seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RUNTIME_EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("DAY16_EVIDENCE_RUN_ID", "unit-fixture")
    for scenario in SCENARIOS:
        evidence(scenario, dict.fromkeys(REQUIRED[scenario], True))
    write_record(tmp_path, "demo-proof", demo_proof())


def test_complete_evidence_and_exclusive_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed(tmp_path, monkeypatch)
    assert json.loads(verify(tmp_path).read_text())["status"] == "passed"
    assert verify(tmp_path, check_existing=True).exists()
    with pytest.raises(FileExistsError):
        verify(tmp_path)


def test_manifest_modification_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(tmp_path, monkeypatch)
    path = verify(tmp_path)
    record = json.loads(path.read_text())
    record["records"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="manifest"):
        verify(tmp_path, check_existing=True)


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


@pytest.mark.parametrize(
    "case",
    [
        "metric",
        "fault",
        "audit",
        "segment",
        "duplicate",
        "operation",
        "duration",
        "trace",
        "missing",
    ],
)
def test_gate_requires_persistent_and_scraped_demo_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    seed(tmp_path, monkeypatch)
    path = tmp_path / "day16-demo-proof.json"
    proof = json.loads(path.read_text())
    lock = proof["cases"][0]
    if case == "metric":
        lock["prometheus_samples"] = []
    elif case == "fault":
        lock["events"] = [event for event in lock["events"] if event["state"] != "FAULT_DETECTED"]
    elif case == "audit":
        proof["audit"]["archives_after"]["0"] = "e" * 64
    elif case == "segment":
        proof["audit"]["segments"][0]["record"]["events"][0]["phase"] = "preparing"
    elif case == "duplicate":
        proof["cases"][1]["device_executions"] = 2
    elif case == "operation":
        lock["events"][0]["operation_id"] = "f" * 32
    elif case == "duration":
        lock["elapsed_seconds"] = 100
    elif case == "trace":
        lock["events"][0]["trace_id"] = None
    if case == "missing":
        path.unlink()
    else:
        path.write_text(json.dumps(proof))
    with pytest.raises((ValueError, FileNotFoundError)):
        verify(tmp_path)
