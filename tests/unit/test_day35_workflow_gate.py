"""Controlled admission fixtures do not replace Runtime fault execution."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from scripts import day35_workflow_gate as gate
from scripts.day34_evidence import COMMANDS
from scripts.day35_evidence import REQUIRED
from scripts.iac.pipeline_evidence import publish


def fixture(
    tmp: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> tuple[Path, Path, dict[str, Any]]:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    expected = {
        "commit": "a" * 40,
        "run_id": "123:2",
        "source_sha256": "b" * 64,
        "day34_source_sha256": "c" * 64,
    }
    baseline = {
        "repository": "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise",
        "candidate_sha": "a" * 40,
        "baseline_sha": "d" * 40,
        "run_id": 123,
        "run_attempt": 2,
    }
    monkeypatch.setattr(gate, "current", lambda: baseline)
    monkeypatch.setattr(gate, "binding", lambda: expected)
    runtime = tmp / "runtime-seed"
    intake = tmp / "intake-seed"
    runtime.mkdir()
    intake.mkdir()

    def write(name: str, value: Any) -> None:
        (runtime / name).write_text(json.dumps(value))

    common = dict(
        version=1,
        decision="READY_FOR_LOCAL_REVIEW",
        ci_verified=True,
        release_authorized=False,
        real_aws_verified=False,
        physical_boot_verified=False,
        simulated_installation=True,
        provenance=expected,
    )
    write("day31-runtime-baseline.json", baseline)
    (intake / "day35-intake.json").write_text(json.dumps(baseline))
    write("day18-ota-execution.json", {})
    write("day19-campaign.json", {})
    (runtime / "day21-postgres.xml").write_text("<testsuites/>")
    write(
        "day34-quality.json",
        dict(
            provenance=expected,
            generated_at_utc=datetime.now(UTC).isoformat(),
            checks={k: dict(exit_code=0, log_sha256="f" * 64) for k in COMMANDS},
        ),
    )
    if fault == "quality":
        q = json.loads((runtime / "day34-quality.json").read_text())
        q["checks"]["ruff"]["exit_code"] = 1
        write("day34-quality.json", q)
    prior = common | {
        "proofs": {
            n: hashlib.sha256((runtime / n).read_bytes()).hexdigest() for n in gate.PRIOR_PROOFS
        }
    }
    write("day34-acceptance.json", prior)
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    props = ET.SubElement(suite, "properties")
    for k, v in expected.items():
        ET.SubElement(props, "property", name=k, value=v)
    for name in sorted(REQUIRED):
        case = ET.SubElement(suite, "testcase", name=name)
        if fault == "skipped_xml":
            ET.SubElement(case, "skipped")
    (runtime / "day35-runtime-faults.xml").write_bytes(ET.tostring(root))
    proof = common | dict(
        generated_at_utc=datetime.now(UTC).isoformat(),
        required_cases=sorted(REQUIRED),
        proofs={n: hashlib.sha256((runtime / n).read_bytes()).hexdigest() for n in gate.PROOFS},
    )
    if fault == "source":
        proof["provenance"] = expected | {"source_sha256": "0" * 64}
    if fault == "release":
        proof["release_authorized"] = True
    if fault == "truthy":
        proof["ci_verified"] = 1
    if fault == "stale":
        proof["generated_at_utc"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    if fault == "case":
        proof["required_cases"] = []
    if fault == "baseline":
        write("day31-runtime-baseline.json", baseline | {"baseline_sha": "e" * 40})
    if fault == "attempt":
        write("day31-runtime-baseline.json", baseline | {"run_attempt": 1})
    write("day35-acceptance.json", proof)
    r = tmp / "runtime"
    i = tmp / "intake"
    publish(runtime, r, "runtime-evidence")
    publish(intake, i, "day35-intake")
    if fault == "tamper":
        (r / "day35-runtime-faults.xml").write_bytes(b"changed")
    if fault == "missing":
        (r / "day35-acceptance.json").unlink()
    if fault == "duplicate_json":
        (r / "day35-acceptance.json").write_text('{"version":1,"version":1}')
    if fault == "nan":
        (r / "day35-acceptance.json").write_text('{"value":NaN}')
    if fault == "nested":
        (r / "unexpected").mkdir()
    needs: dict[str, Any] = {"intake": {"result": "success"}, "acceptance": {"result": "success"}}
    if fault in {"failure", "cancelled", "skipped"}:
        needs["acceptance"]["result"] = fault
    if fault == "bad_needs":
        needs["intake"] = None
    return r, i, needs


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "failure",
        "cancelled",
        "skipped",
        "source",
        "release",
        "truthy",
        "stale",
        "case",
        "baseline",
        "attempt",
        "tamper",
        "missing",
        "duplicate_json",
        "nan",
        "nested",
        "skipped_xml",
        "bad_needs",
        "quality",
    ],
)
def test_admission_refuses_invalid_transport_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    r, i, needs = fixture(tmp_path, monkeypatch, fault)
    if fault == "none":
        value = gate.evaluate(r, i, needs)
        assert (
            value["decision"] == "READY_FOR_LOCAL_REVIEW" and value["release_authorized"] is False
        )
        assert value["baseline"]["run_attempt"] == 2
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            gate.evaluate(r, i, needs)


def test_failed_upstream_writes_blocked_diagnostic_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, i, needs = fixture(tmp_path, monkeypatch, "cancelled")
    output = tmp_path / "result.json"
    monkeypatch.setenv("PIPELINE_NEEDS", json.dumps(needs))
    monkeypatch.setattr(
        "sys.argv", ["gate", "--runtime", str(r), "--intake", str(i), "--output", str(output)]
    )
    assert gate.main() == 1
    assert json.loads(output.read_text())["decision"] == "BLOCKED"
    with pytest.raises(FileExistsError):
        gate.main()


def test_workflow_keeps_readonly_dag_and_attempt_scoped_artifacts() -> None:
    from tests.unit.iac.test_workflow import assert_pinned_steps, read

    w = read(".github/workflows/day35.yml")
    assert_pinned_steps(w)
    assert w["concurrency"]["cancel-in-progress"] == "false"
    assert w["jobs"]["acceptance"]["needs"] == ["intake"]
    final = w["jobs"]["day35"]
    assert final["needs"] == ["intake", "acceptance"] and final["if"] == "${{ always() }}"
    admission = next(
        s
        for s in final["steps"]
        if s.get("name") == "Evaluate Day35 evidence and write fail-closed decision"
    )
    assert (
        admission["if"] == "${{ always() }}"
        and admission["env"]["PIPELINE_NEEDS"] == "${{ toJSON(needs) }}"
    )
    upload = final["steps"][-1]
    assert upload["if"] == "${{ always() }}"
    assert (
        upload["with"]["name"]
        == "day35-workflow-result-${{ github.run_id }}-${{ github.run_attempt }}"
    )


def test_intake_upload_includes_the_hidden_sealed_directory() -> None:
    from tests.unit.iac.test_workflow import read

    workflow = read(".github/workflows/day35.yml")
    upload = workflow["jobs"]["intake"]["steps"][-1]
    assert upload["with"]["path"] == ".day35-sealed-intake"
    assert upload["with"]["include-hidden-files"] == "true"
    assert upload["with"]["if-no-files-found"] == "error"
