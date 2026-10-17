from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from connected_vehicle.ota.execution_contracts import SignedManifest
from scripts import contracts
from scripts.day17_release import ROOT, readiness_digest


def test_cvota2_golden_bytes_and_signature_do_not_drift() -> None:
    vector = json.loads((ROOT / "tests/fixtures/day18/manifest-v2-golden.json").read_text())
    manifest = SignedManifest.model_validate(vector["manifest"])
    assert hashlib.sha256(manifest.canonical()).hexdigest() == vector["canonical_sha256"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(vector["public_key"])).verify(
        base64.b64decode(vector["signature"]), manifest.canonical()
    )


def test_missing_day17_contract_is_rejected_even_if_main_did_not_have_ota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = contracts.schemas()
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts/platform-v1.json").write_text(
        json.dumps({key: value for key, value in current.items() if not key.startswith("ota-")})
    )
    del current["ota-ecu/1.0"]
    monkeypatch.setattr(contracts, "schemas", lambda: current)
    assert any(
        "pinned Day17 OTA contract removed" in error for error in contracts.check(ROOT, tmp_path)
    )


@pytest.mark.parametrize(
    "relative",
    [
        ".github/workflows/ci.yml",
        "scripts/iac/checkov.yaml",
        "scripts/iac/scan_exceptions.json",
        "scripts/iac/requirements.txt",
    ],
)
def test_iac_gate_inputs_participate_in_evidence_digest(
    monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    original = Path.read_text
    expected = readiness_digest()

    def altered(path: Path, *args: Any, **kwargs: Any) -> str:
        data = original(path, *args, **kwargs)
        return data + "\n# changed gate input\n" if path == ROOT / relative else data

    monkeypatch.setattr(Path, "read_text", altered)
    assert readiness_digest() != expected
