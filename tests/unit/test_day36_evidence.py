"""Mutation rejection tests; synthetic fixtures are never deployment proof."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from scripts import day36_evidence as gate


@pytest.fixture
def proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(gate, "verify_supply", lambda _: {"decision": "SUPPLY_CHAIN_VERIFIED"})
    monkeypatch.setattr(gate, "command", lambda _: "a" * 40)
    monkeypatch.setattr(gate, "application_hash", lambda _: "c" * 64)
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.delenv("GITHUB_RUN_ATTEMPT", raising=False)
    snapshot = {"remote_commands": {"count": 1}, "outbox_events": {"count": 1}}
    staging = {
        "candidate_sha": "a" * 40,
        "run_id": "local",
        "run_attempt": "local",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": "local_staging",
        "production_authorized": False,
        "image_digest": "sha256:" + "1" * 64,
        "baseline_image_digest": "sha256:" + "2" * 64,
        "before": snapshot,
        "after": snapshot,
        "schema_rollback_executed": False,
        "rollback_verified": True,
        "database_consistency_verified": True,
        "stable_ingress_verified": True,
        "runtime_security_verified": True,
        "smoke_test": {"authenticated_command": True, "campaign_query": True},
        "faults": [
            {"name": name, "rejected": True, "rollback_verified": True}
            for name in ("startup_exit", "readiness_503", "candidate_sigkill")
        ],
    }
    images = {
        "candidate_sha": "a" * 40,
        "candidate": {
            "revision": "a" * 40,
            "image_digest": staging["image_digest"],
            "application_sha256": "c" * 64,
        },
        "baseline": {"image_digest": staging["baseline_image_digest"]},
    }
    (tmp_path / "staging.json").write_text(json.dumps(staging))
    (tmp_path / "images.json").write_text(json.dumps(images))
    suite = ET.Element("testsuite")
    properties = {
        "candidate_sha": "a" * 40,
        "run_id": "local",
        "run_attempt": "local",
        "staging_sha256": hashlib.sha256((tmp_path / "staging.json").read_bytes()).hexdigest(),
    }
    for name in sorted(gate.REQUIRED):
        case = ET.SubElement(suite, "testcase", name=name)
        props = ET.SubElement(case, "properties")
        for key, value in properties.items():
            ET.SubElement(props, "property", name=key, value=value)
    ET.ElementTree(suite).write(tmp_path / "staging.xml")
    contracts = ET.Element("testsuite")
    ET.SubElement(contracts, "testcase", name="test_workflow_five_nodes_and_python_interfaces")
    props = ET.SubElement(contracts, "properties")
    for key, value in {
        "candidate_sha": "a" * 40,
        "run_id": "local",
        "run_attempt": "local",
    }.items():
        ET.SubElement(props, "property", name=key, value=value)
    ET.ElementTree(contracts).write(tmp_path / "contracts.xml")
    return tmp_path


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "commit",
        "attempt",
        "production",
        "image",
        "same-image",
        "drift",
        "missing-fault",
        "duplicate-fault",
        "truthy",
        "schema-downgrade",
        "stale",
        "missing-case",
        "duplicate-case",
        "skipped",
        "failed",
        "unbound",
        "ci-missing",
    ],
)
def test_staging_admission_rejects_incomplete_proof(proof: Path, mutation: str) -> None:
    raw = proof / "staging.json"
    staging: dict[str, Any] = json.loads(raw.read_text())
    if mutation == "commit":
        staging["candidate_sha"] = "b" * 40
    elif mutation == "attempt":
        staging["run_attempt"] = "9"
    elif mutation == "production":
        staging["production_authorized"] = True
    elif mutation == "image":
        staging["image_digest"] = "mutable:latest"
    elif mutation == "same-image":
        staging["baseline_image_digest"] = staging["image_digest"]
    elif mutation == "drift":
        staging["after"]["remote_commands"]["count"] = 2
    elif mutation == "missing-fault":
        staging["faults"].pop()
    elif mutation == "duplicate-fault":
        staging["faults"][2] = staging["faults"][0]
    elif mutation == "truthy":
        staging["rollback_verified"] = "true"
    elif mutation == "schema-downgrade":
        staging["schema_rollback_executed"] = True
    elif mutation == "stale":
        staging["generated_at"] = "2020-01-01T00:00:00+00:00"
    raw.write_text(json.dumps(staging))
    tree = ET.parse(proof / "staging.xml")
    case = tree.findall("testcase")[0]
    if mutation == "missing-case":
        tree.getroot().remove(case)
    elif mutation == "duplicate-case":
        tree.getroot().append(case)
    elif mutation in {"skipped", "failed"}:
        ET.SubElement(case, "skipped" if mutation == "skipped" else "failure")
    elif mutation == "unbound":
        case.find("properties").clear()  # type: ignore[union-attr]
    tree.write(proof / "staging.xml")
    if mutation == "none":
        result = gate.verify(proof)
        assert result["decision"] == "LOCAL_STAGING_VERIFIED"
        assert result["release_authorized"] is False
    else:
        with pytest.raises((ValueError, OSError)):
            gate.verify(proof, ci=mutation == "ci-missing")
