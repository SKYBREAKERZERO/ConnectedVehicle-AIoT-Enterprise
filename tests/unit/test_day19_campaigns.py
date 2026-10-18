from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from connected_vehicle.ota.campaign_contracts import CampaignCreate, CampaignFreeze
from scripts import contracts
from scripts import day19_evidence as gate
from scripts.day16_evidence import provenance
from scripts.day17_release import read_json, write_json
from scripts.day18_evidence import evaluate as evaluate18
from tests.unit.test_day18_evidence import seed as seed18


@pytest.mark.parametrize(
    "change",
    [
        {"canary_size": 0},
        {"wave_size": 101},
        {"max_failures": 1},
        {"observation_seconds": -1},
        {"wave_timeout_seconds": 29},
        {"security_version": True},
        {"signature": "x" * 88},
        {"tenant_id": "forged"},
        {"canary_size": True},
        {"wave_size": 1.5},
        {"key_id": "invalid key name"},
        {"name": "invalid\u0000name"},
    ],
)
def test_invalid_campaign_intents_fail_validation(change: dict[str, Any]) -> None:
    body = dict(
        operation_id=uuid4(),
        name="rollout",
        release_id=uuid4(),
        security_version=1,
        key_id="publisher-1",
        signature=base64.b64encode(bytes(64)).decode(),
        canary_size=1,
        wave_size=5,
    )
    with pytest.raises(ValidationError):
        CampaignCreate.model_validate(body | change)


def test_duplicate_or_empty_snapshot_targets_are_rejected() -> None:
    ecu = uuid4()
    for ids in ([], [ecu, ecu]):
        with pytest.raises(ValidationError):
            CampaignFreeze(operation_id=uuid4(), ecu_ids=ids)


def seed(directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed18(directory, monkeypatch)
    write_json(directory / "day18-acceptance.json", evaluate18(directory))
    write_json(
        directory / "day19-campaign.json",
        dict(
            version=1,
            profile="local_drill",
            generated_at_utc=datetime.now(UTC).isoformat(),
            provenance=provenance(),
            day19_sha256=gate.source_digest(),
            checks={key: True for key in gate.REQUIRED},
            device_successes=4,
            real_aws_verified=False,
            physical_boot_verified=False,
            simulated_installation=True,
        ),
    )


def test_campaign_evidence_is_immutable_and_prerequisite_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(tmp_path, monkeypatch)
    record = gate.evaluate(tmp_path)
    write_json(tmp_path / "day19-acceptance.json", record)
    assert gate.verify(tmp_path) == record
    with pytest.raises(FileExistsError):
        write_json(tmp_path / "day19-acceptance.json", record)
    (tmp_path / "day18-acceptance.json").unlink()
    with pytest.raises(FileNotFoundError):
        gate.verify(tmp_path)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "failed",
        "truthy",
        "source",
        "run",
        "stale",
        "future",
        "naive",
        "aws",
        "hardware",
        "count",
        "simulated",
    ],
)
def test_campaign_gate_rejects_false_or_mixed_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    seed(tmp_path, monkeypatch)
    path = tmp_path / "day19-campaign.json"
    report = read_json(path)
    key = next(iter(gate.REQUIRED))
    if fault == "missing":
        report["checks"].pop(key)
    elif fault in {"failed", "truthy"}:
        report["checks"][key] = False if fault == "failed" else 1
    elif fault == "source":
        report["day19_sha256"] = "0" * 64
    elif fault == "run":
        report["provenance"]["run_id"] = "another-run"
    elif fault in {"stale", "future"}:
        report["generated_at_utc"] = (
            datetime.now(UTC) + timedelta(seconds=901 if fault == "future" else -901)
        ).isoformat()
    elif fault == "naive":
        report["generated_at_utc"] = datetime.now(UTC).replace(tzinfo=None).isoformat()
    elif fault == "aws":
        report["real_aws_verified"] = True
    elif fault == "hardware":
        report["physical_boot_verified"] = True
    elif fault == "count":
        report["device_successes"] = "4"
    else:
        report["simulated_installation"] = False
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError):
        gate.evaluate(tmp_path)


def test_day18_execution_contract_cannot_disappear_when_main_has_no_ota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = contracts.schemas()
    current.pop("ota-claim/2.0")
    monkeypatch.setattr(contracts, "schemas", lambda: current)
    assert any("pinned Day18 contract removed" in e for e in contracts.check(contracts.ROOT))
