"""Day33 refuses incomplete latest attempts and changed server artifact bytes."""

import hashlib
import io
import json
import zipfile

import pytest

from scripts.iac.day33_independent_verifier import REQUIRED_JOBS, verify_artifact, verify_run


def fixture():
    run = dict(
        id=17,
        head_sha="a" * 40,
        run_attempt=14,
        status="completed",
        conclusion="success",
        run_started_at="2026-11-02T00:00:00Z",
    )
    jobs = [
        dict(name=name, status="completed", conclusion="success") for name in sorted(REQUIRED_JOBS)
    ]
    return run, jobs


def test_complete_latest_run():
    run, jobs = fixture()
    verify_run(run, jobs, "a" * 40, 14)


@pytest.mark.parametrize(
    "fault",
    ["cancelled", "old_attempt", "wrong_head", "missing", "skipped", "cancelled_job", "renamed"],
)
def test_reject_run_fault(fault):
    run, jobs = fixture()
    if fault == "cancelled":
        run["conclusion"] = "cancelled"
    if fault == "old_attempt":
        run["run_attempt"] = 13
    if fault == "wrong_head":
        run["head_sha"] = "b" * 40
    if fault == "missing":
        jobs.pop()
    if fault == "cancelled_job":
        jobs[0]["conclusion"] = "cancelled"
    if fault == "renamed":
        jobs[0]["name"] = "unrelated successful job"
    if fault == "skipped":
        jobs[0]["conclusion"] = "skipped"
    with pytest.raises(ValueError):
        verify_run(run, jobs, "a" * 40, 14)


@pytest.mark.parametrize(
    "fault", ["none", "tamper", "old_attempt", "missing", "proof_mismatch", "expired"]
)
def test_artifact_faults(fault):
    run, _ = fixture()
    report = dict(
        status="passed",
        production_apply_enabled=False,
        release_authorized=False,
        provenance=dict(day31_commit="b" * 40, day31_run_id="17:14"),
    )
    if fault == "old_attempt":
        report["provenance"]["day31_run_id"] = "17:13"
    report["proof_sha256"] = {
        name: hashlib.sha256(b"{}").hexdigest()
        for name in ["contracts.json", "summary.json", "day32-deployment.json"]
    }
    if fault == "proof_mismatch":
        report["proof_sha256"]["summary.json"] = "0" * 64
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr("day32-acceptance.json", json.dumps(report))
        for name in ["day32-deployment.json", "contracts.json", "summary.json"]:
            if fault != "missing":
                z.writestr(name, "{}")
    raw = stream.getvalue()
    meta = dict(
        name="day32-iac-acceptance",
        expired=False,
        workflow_run=dict(id=17),
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        created_at=run["run_started_at"],
    )
    if fault == "expired":
        meta["expired"] = True
    if fault == "tamper":
        raw += b"changed"
    if fault == "none":
        assert verify_artifact(raw, meta, run, "b" * 40) == report
    else:
        with pytest.raises(ValueError):
            verify_artifact(raw, meta, run, "b" * 40)


def test_active_iac_run_is_not_auto_cancelled():
    from tests.unit.iac.test_workflow import read

    workflow = read(".github/workflows/ci.yml")
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    assert (
        workflow["concurrency"]["group"]
        == "iac-${{ github.event.pull_request.number || github.ref }}"
    )
    assert workflow["permissions"] == {"contents": "read"}
