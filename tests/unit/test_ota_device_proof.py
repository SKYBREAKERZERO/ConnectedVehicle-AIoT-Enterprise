from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from connected_vehicle.ota.device_proof import proof_headers, verify_proof


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "wrong_key",
        "body",
        "method",
        "ecu",
        "device",
        "expired",
        "future",
        "install_denied",
        "wrong_vehicle",
    ],
)
def test_ecu_proof_binds_identity_target_request_and_time(tmp_path: Path, fault: str) -> None:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "tenant": {
                    "device": {
                        "ecu": {
                            "vehicle_id": "vehicle",
                            "install_allowed": fault != "install_denied",
                            "public_key": base64.b64encode(
                                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                            ).decode(),
                        }
                    }
                }
            }
        )
    )
    values: dict[str, Any] = dict(
        method="POST",
        path="/claim",
        body=b'{"operation":"one"}',
        tenant="tenant",
        vehicle="vehicle",
        ecu="ecu",
        device="device",
    )
    headers = proof_headers(
        Ed25519PrivateKey.generate() if fault == "wrong_key" else key,
        **values,
        nonce=str(uuid4()),
        timestamp=str(
            int(time.time()) + (-121 if fault == "expired" else 121 if fault == "future" else 0)
        ),
    )
    if fault in {"method", "ecu", "device", "body", "wrong_vehicle"}:
        values[{"wrong_vehicle": "vehicle"}.get(fault, fault)] = (
            b"{}" if fault == "body" else "other"
        )
    if fault == "none":
        assert verify_proof(path, **values, headers=headers) == headers["X-ECU-Nonce"]
    else:
        with pytest.raises(ValueError):
            verify_proof(path, **values, headers=headers)
