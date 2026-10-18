from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from connected_vehicle.ota.artifacts import verify_signature
from connected_vehicle.ota.execution_contracts import SignedManifest
from scripts.ota_key_registry import migrate
from tests.unit.test_day18_ota import fixture_claim


@pytest.mark.parametrize(
    "fault", ["expired", "future", "revoked", "legacy_registry", "legacy_protocol"]
)
def test_publisher_lifecycle_and_protocol_fail_closed(tmp_path: Path, fault: str) -> None:
    claim, path, _ = fixture_claim(tmp_path)
    registry = json.loads(path.read_text())
    entry = registry["tenants"]["tenant-a"]["key-1"]
    now = datetime.now(UTC)
    if fault == "expired":
        entry["not_after"] = (now - timedelta(seconds=1)).isoformat()
    elif fault == "future":
        entry["not_before"] = (now + timedelta(seconds=1)).isoformat()
    elif fault == "revoked":
        entry["revoked"] = True
    elif fault == "legacy_registry":
        registry = {"tenant-a": {"key-1": entry["public_key"]}}
    else:
        with pytest.raises(ValidationError):
            SignedManifest.model_validate(
                claim.manifest.model_dump(mode="json") | {"protocol": "cv-ota/1"}
            )
        return
    path.write_text(json.dumps(registry))
    with pytest.raises(ValueError):
        verify_signature(path, claim.manifest, claim.signature)


def test_explicit_registry_conversion_preserves_source_and_is_not_activation(
    tmp_path: Path,
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    audit = tmp_path / "audit.json"
    old.write_text(json.dumps({"tenant-a": {"key-1": base64.b64encode(b"x" * 32).decode()}}))
    original = old.read_bytes()
    values = dict(
        not_before="2020-01-01T00:00:00+00:00",
        not_after="2099-01-01T00:00:00+00:00",
        operation=str(uuid4()),
        actor="key-operator",
        reason="reviewed migration",
    )
    migrate(old, new, audit, **values)
    assert old.read_bytes() == original
    assert json.loads(new.read_text())["protocol"] == "cv-ota-keys/1"
    assert json.loads(audit.read_text())["activated"] is False
    with pytest.raises(FileExistsError):
        migrate(old, new, audit, **values)
    with pytest.raises(FileExistsError):
        migrate(old, old, tmp_path / "another.json", **values)
