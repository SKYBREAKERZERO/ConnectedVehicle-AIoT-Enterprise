"""Offline models: callbacks below deliberately simulate a trusted authority."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.plan_admission import BOUND, canonical_digest
from scripts.iac.release_admission import ReleaseStore
from tests.unit.iac.test_plan_admission import NOW, PLAN, manifest


@pytest.fixture(scope="module", autouse=True)
def stamp_day27(record_testsuite_property: Callable[[str, object], None]) -> None:
    from scripts.iac.day27_evidence import source_digest

    for name, value in {
        "day27_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day27_run_id": run_identity(),
        "day27_source_sha256": source_digest(),
    }.items():
        record_testsuite_property(name, value)


def bundle(request_id: str = "release-1") -> dict[str, Any]:
    data = manifest()
    source = "d" * 64
    evidence = {
        "request_id": request_id,
        "manifest_sha256": canonical_digest(data),
        "source_sha256": source,
        "run_id": data["run_id"],
        "repository": "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise",
        "workflow": ".github/workflows/ci.yml",
        "conclusion": "success",
        "created_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
    }
    return {
        "manifest": data,
        "plan": PLAN,
        "expected": {k: data[k] for k in BOUND},
        "evidence": evidence,
        "source": source,
        "now": NOW,
        "evidence_authority": lambda _: True,
    }


def request(store: ReleaseStore, data: dict[str, Any], request_id: str = "release-1") -> None:
    store.request(request_id, data["manifest"], data["evidence"], data["source"], "release-author")


def receipt(data: dict[str, Any], request_id: str = "release-1") -> dict[str, Any]:
    binding = {k: data[k] for k in ("manifest", "evidence", "source")}
    return {
        "request_id": request_id,
        "binding_sha256": canonical_digest(binding),
        "reviewer": "independent-reviewer",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "approval_id": "approval-1",
    }


def approve(
    store: ReleaseStore, data: dict[str, Any], request_id: str = "release-1"
) -> dict[str, Any]:
    store.advance(request_id, "VERIFIED", **data)
    data = {**data, "approval": receipt(data, request_id), "approval_authority": lambda _: True}
    store.advance(request_id, "APPROVED", **data)
    return data


def test_ordered_admission_is_persistent_and_ready_is_one_shot(tmp_path: Path) -> None:
    path = tmp_path / "model.sqlite"
    store = ReleaseStore(path)
    data = bundle()
    request(store, data)
    data = approve(store, data)
    ReleaseStore(path).advance("release-1", "READY", **data)
    assert store.state("release-1") == "READY"
    with pytest.raises(ValueError, match="illegal transition"):
        store.advance("release-1", "READY", **data)
    with sqlite3.connect(path) as connection:
        import json

        saved_approval = json.loads(
            connection.execute("SELECT approval FROM releases WHERE id='release-1'").fetchone()[0]
        )
        assert saved_approval["reviewer"] == "independent-reviewer"
        assert saved_approval["request_id"] == "release-1"
        assert [
            row[0] for row in connection.execute("SELECT state FROM events ORDER BY sequence")
        ] == ["REQUESTED", "VERIFIED", "APPROVED", "READY"]


@pytest.mark.parametrize("target", ["READY", "APPROVED", "REJECTED", "INTERRUPTED", "EXECUTING"])
def test_states_cannot_skip_verification_or_approval(tmp_path: Path, target: str) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    with pytest.raises(ValueError, match="illegal transition"):
        store.advance("release-1", target, **data)
    assert store.state("release-1") == "REQUESTED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commit", "b" * 40),
        ("account", "999999999999"),
        ("environment", "staging"),
        ("run_id", "99999:1"),
        ("run_id", "12345:2"),
        ("state_serial", 99),
        ("state_lineage", "22222222-2222-2222-2222-222222222222"),
        ("lockfile_sha256", "f" * 64),
    ],
)
def test_post_approval_trusted_context_change_rejected(
    tmp_path: Path, field: str, value: Any
) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    data = approve(store, data)
    data["expected"][field] = value
    with pytest.raises(ValueError):
        store.advance("release-1", "READY", **data)
    assert store.state("release-1") == "REJECTED"
    with pytest.raises(ValueError, match="illegal transition"):
        store.advance("release-1", "READY", **data)


@pytest.mark.parametrize("field", ["plan", "source", "evidence", "manifest"])
def test_post_approval_plan_source_or_evidence_change_rejected(tmp_path: Path, field: str) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    data = approve(store, data)
    if field == "plan":
        data["plan"] += b"modified"
    if field == "source":
        data["source"] = "e" * 64
    if field == "evidence":
        data["evidence"]["source_sha256"] = "e" * 64
    if field == "manifest":
        data["manifest"]["plan_sha256"] = "e" * 64
    with pytest.raises(ValueError):
        store.advance("release-1", "READY", **data)
    assert store.state("release-1") == "REJECTED"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_id", "99999:1"),
        ("run_id", "12345:2"),
        ("source_sha256", "e" * 64),
        ("manifest_sha256", "f" * 64),
        ("repository", "attacker/repo"),
        ("workflow", ".github/workflows/other.yml"),
        ("conclusion", "failure"),
        ("expires_at", NOW.isoformat()),
        ("created_at", (NOW + timedelta(minutes=1)).isoformat()),
    ],
)
def test_old_foreign_or_tampered_evidence_denied(tmp_path: Path, field: str, value: Any) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    data["evidence"][field] = value
    request(store, data)
    with pytest.raises(ValueError):
        store.advance("release-1", "VERIFIED", **data)
    assert store.state("release-1") == "REJECTED"


@pytest.mark.parametrize(
    "mutation", ["self", "expired", "revoked", "missing", "request", "binding", "id", "exception"]
)
def test_approval_rechecked_and_failures_persist(tmp_path: Path, mutation: str) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    data = approve(store, data)
    if mutation == "self":
        data["approval"]["reviewer"] = "RELEASE-AUTHOR"
    if mutation == "expired":
        data["approval"]["expires_at"] = NOW.isoformat()
    if mutation == "revoked":
        data["approval_authority"] = lambda _: False
    if mutation == "missing":
        data["approval"] = None
    if mutation == "request":
        data["approval"]["request_id"] = "release-2"
    if mutation == "binding":
        data["approval"]["binding_sha256"] = "f" * 64
    if mutation == "id":
        data["approval"]["approval_id"] = ""
    if mutation == "exception":

        def unavailable(_: Any) -> bool:
            raise OSError("trusted authority unavailable")

        data["approval_authority"] = unavailable
    with pytest.raises(ValueError):
        store.advance("release-1", "READY", **data)
    assert ReleaseStore(tmp_path / "model.sqlite").state("release-1") == "REJECTED"


def test_new_request_cannot_reuse_old_request_approval(tmp_path: Path) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    old = approve(store, data)["approval"]
    data = bundle("release-2")
    request(store, data, "release-2")
    store.advance("release-2", "VERIFIED", **data)
    with pytest.raises(ValueError):
        store.advance(
            "release-2", "APPROVED", **data, approval=old, approval_authority=lambda _: True
        )
    assert store.state("release-2") == "REJECTED"


def test_same_backend_concurrent_requests_have_one_ready_winner(tmp_path: Path) -> None:
    path = tmp_path / "model.sqlite"
    store = ReleaseStore(path)
    data = bundle()
    prepared = {}
    for request_id in ("release-1", "release-2"):
        data = bundle(request_id)
        request(store, data, request_id)
        prepared[request_id] = approve(store, deepcopy(data), request_id)

    def reserve(request_id: str) -> bool:
        try:
            ReleaseStore(path).advance(request_id, "READY", **prepared[request_id])
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(reserve, prepared)).count(True) == 1
    assert sorted(store.state(key) for key in prepared) == ["READY", "REJECTED"]


def test_crash_after_ready_never_resumes_or_releases_reservation(tmp_path: Path) -> None:
    path = tmp_path / "model.sqlite"
    store, data = ReleaseStore(path), bundle()
    request(store, data)
    data = approve(store, data)
    store.advance("release-1", "READY", **data)
    # Independent process exits abruptly; the durable reservation survives.
    code = (
        "from pathlib import Path; import os,sys; "
        "from scripts.iac.release_admission import ReleaseStore; "
        "s=ReleaseStore(Path(sys.argv[1])); assert s.state('release-1')=='READY'; os._exit(27)"
    )
    result = subprocess.run([sys.executable, "-c", code, str(path)], cwd=ROOT, timeout=10)
    assert result.returncode == 27 and store.state("release-1") == "READY"
    store.interrupt("release-1")
    assert store.state("release-1") == "INTERRUPTED"
    with pytest.raises(ValueError, match="illegal transition"):
        store.advance("release-1", "READY", **data)
    fresh = bundle("release-2")
    request(store, fresh, "release-2")
    with pytest.raises(ValueError, match="illegal transition"):
        store.advance("release-2", "READY", **fresh)
    fresh = approve(store, fresh, "release-2")
    with pytest.raises(ValueError, match="reserved|spent"):
        store.advance("release-2", "READY", **fresh)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM spent").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM holders").fetchone()[0] == 1


def test_expired_or_revoked_evidence_cannot_reach_ready(tmp_path: Path) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data)
    data = approve(store, data)
    data["evidence_authority"] = lambda _: False
    with pytest.raises(ValueError):
        store.advance("release-1", "READY", **data)
    assert store.state("release-1") == "REJECTED"


def test_evidence_cannot_move_to_a_new_request(tmp_path: Path) -> None:
    store, data = ReleaseStore(tmp_path / "model.sqlite"), bundle()
    request(store, data, "release-2")
    with pytest.raises(ValueError):
        store.advance("release-2", "VERIFIED", **data)
    assert store.state("release-2") == "REJECTED"


def test_day27_report_rejects_relabel_or_missing_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xml.etree import ElementTree

    from scripts.iac import day27_evidence as module

    monkeypatch.setattr(
        module,
        "day26_evidence",
        lambda _: {
            "provenance": {"day26_commit": "a" * 40, "day26_run_id": "123:1"},
            "junit_sha256": "b" * 64,
        },
    )
    doc = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(doc, "testsuite")
    props = ElementTree.SubElement(suite, "properties")
    for key, value in {
        "day27_commit": "a" * 40,
        "day27_run_id": "123:1",
        "day27_source_sha256": module.source_digest(),
    }.items():
        ElementTree.SubElement(props, "property", name=key, value=value)
    for name in module.SCENARIOS:
        ElementTree.SubElement(suite, "testcase", name=name)
    xml = tmp_path / "report.xml"
    ElementTree.ElementTree(doc).write(xml)
    assert module.evidence(xml)["production_apply_enabled"] is False
    props[1].set("value", "999:1")
    ElementTree.ElementTree(doc).write(xml)
    with pytest.raises(ValueError, match="attestation"):
        module.evidence(xml)
    props[1].set("value", "123:1")
    suite.remove(suite[-1])
    ElementTree.ElementTree(doc).write(xml)
    with pytest.raises(ValueError, match="scenarios"):
        module.evidence(xml)


@pytest.mark.parametrize(
    "mutation", ["none", "run", "source", "failure", "duplicate", "unlock", "aws"]
)
def test_fault_report_cannot_be_relabelled_or_hide_unsafe_recovery(
    tmp_path: Path, mutation: str
) -> None:
    import json
    from xml.etree import ElementTree

    from scripts.iac.day27_evidence import fault_evidence

    expected = {"day27_commit": "a" * 40, "day27_run_id": "123:1", "day27_source_sha256": "b" * 64}
    doc = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(doc, "testsuite")
    props = ElementTree.SubElement(suite, "properties")
    for key, value in expected.items():
        ElementTree.SubElement(props, "property", name=key, value=value)
    case = ElementTree.SubElement(
        suite, "testcase", name="test_native_lock_survives_holder_process_termination"
    )
    result = {
        "provenance": expected,
        "status": "passed",
        "localstack_only": True,
        "holder_process_killed": True,
        "orphan_lock_retained": True,
        "state_unchanged": True,
        "aws_verified": False,
        "automatic_force_unlock": False,
        "apply_performed": False,
    }
    if mutation == "run":
        props[1].set("value", "999:1")
    if mutation == "source":
        result["provenance"] = {**expected, "day27_source_sha256": "c" * 64}
    if mutation == "failure":
        ElementTree.SubElement(case, "failure")
    if mutation == "duplicate":
        ElementTree.SubElement(
            suite, "testcase", name="test_native_lock_survives_holder_process_termination"
        )
    if mutation == "unlock":
        result["automatic_force_unlock"] = True
    if mutation == "aws":
        result["aws_verified"] = True
    xml = tmp_path / "lock.xml"
    path = tmp_path / "lock.json"
    ElementTree.ElementTree(doc).write(xml)
    path.write_text(json.dumps(result), encoding="utf-8")
    if mutation == "none":
        assert fault_evidence(xml, path, expected)["status"] == "passed"
    else:
        with pytest.raises(ValueError):
            fault_evidence(xml, path, expected)
