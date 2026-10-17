"""Independent, ECU-scoped proof of possession; JWT vehicle scope is insufficient."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from connected_vehicle.ota.artifacts import unique_pairs
from connected_vehicle.ota.execution_contracts import ClaimResult, InstallationProof


def ecu_key(registry: Path, tenant: str, vehicle: str, ecu: str, device: str) -> Ed25519PublicKey:
    with registry.open("rb") as stream:
        encoded = stream.read(65537)
    if len(encoded) > 65536:
        raise ValueError("Oversized ECU registry")
    entry = json.loads(encoded, object_pairs_hook=unique_pairs)[tenant][device][ecu]
    if entry["vehicle_id"] != vehicle or entry["install_allowed"] is not True:
        raise ValueError("ECU installation not authorized")
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"], validate=True))


def verify_boot(
    registry: Path, claim: ClaimResult, proof: InstallationProof, *, observed: bool = False
) -> None:
    expected = (
        claim.manifest.tenant_id,
        claim.job.vehicle_id,
        claim.job.ecu_id,
        claim.device_id,
        claim.job.id,
        claim.claim_token,
        claim.install_challenge,
    )
    actual = (
        proof.tenant_id,
        proof.vehicle_id,
        proof.ecu_id,
        proof.device_id,
        proof.job_id,
        proof.claim_token,
        proof.challenge,
    )
    if (
        expected != actual
        or proof.booted_at < claim.job.created_at
        or proof.booted_at > datetime.now(UTC) + timedelta(seconds=60)
    ):
        raise ValueError("Boot proof target, claim or time mismatch")
    if not observed and (proof.sha256, proof.firmware_version, proof.security_version) != (
        claim.manifest.sha256,
        claim.manifest.version,
        claim.manifest.security_version,
    ):
        raise ValueError("Boot result differs from signed target")
    ecu_key(
        registry, proof.tenant_id, str(proof.vehicle_id), str(proof.ecu_id), proof.device_id
    ).verify(base64.b64decode(proof.signature, validate=True), proof.canonical())


def message(
    method: str,
    path: str,
    body: bytes,
    tenant: str,
    vehicle: str,
    ecu: str,
    device: str,
    nonce: str,
    timestamp: str,
) -> bytes:
    parts = (
        "CV-ECU-PROOF/1",
        method.upper(),
        path,
        hashlib.sha256(body).hexdigest(),
        tenant,
        vehicle,
        ecu,
        device,
        nonce,
        timestamp,
    )
    if any("\n" in part or "\r" in part for part in parts):
        raise ValueError("Invalid ECU proof field")
    return "\n".join(parts).encode()


def proof_headers(
    key: Ed25519PrivateKey,
    *,
    method: str,
    path: str,
    body: bytes,
    tenant: str,
    vehicle: str,
    ecu: str,
    device: str,
    nonce: str,
    timestamp: str,
) -> dict[str, str]:
    signature = key.sign(
        message(method, path, body, tenant, vehicle, ecu, device, nonce, timestamp)
    )
    return {
        "X-ECU-Nonce": nonce,
        "X-ECU-Time": timestamp,
        "X-ECU-Signature": base64.b64encode(signature).decode(),
    }


def verify_proof(
    registry: Path,
    *,
    method: str,
    path: str,
    body: bytes,
    tenant: str,
    vehicle: str,
    ecu: str,
    device: str,
    headers: Any,
) -> str:
    with registry.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized ECU trust registry")
    entries = json.loads(data, object_pairs_hook=unique_pairs)
    try:
        entry = entries[tenant][device][ecu]
        if entry["vehicle_id"] != vehicle or entry["install_allowed"] is not True:
            raise ValueError("ECU installation is not authorized")
        nonce, timestamp = headers["X-ECU-Nonce"], headers["X-ECU-Time"]
        if str(UUID(nonce)) != nonce or str(int(timestamp)) != timestamp:
            raise ValueError("Noncanonical ECU proof")
        if abs(time.time() - int(timestamp)) > 60:
            raise ValueError("Expired ECU proof")
        signature = base64.b64decode(headers["X-ECU-Signature"], validate=True)
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(entry["public_key"], validate=True)
        )
        key.verify(
            signature, message(method, path, body, tenant, vehicle, ecu, device, nonce, timestamp)
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ValueError("Unauthorized ECU proof") from exc
    return str(nonce)
