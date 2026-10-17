"""Separate local boot-confirmation process; never executes downloaded image bytes."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sqlite3
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connected_vehicle.ota.artifacts import verify_signature
from connected_vehicle.ota.execution_contracts import ClaimResult, InstallationProof
from simulators.ota_device.store import DeviceStore, exclusive


def _probe(
    root: Path,
    claim: ClaimResult,
    key_file: Path,
    trust: Path,
    *,
    observed: bool = False,
    fail_health: bool = False,
    max_bytes: int = 32 * 1024**2,
) -> InstallationProof:
    with sqlite3.connect(root / "device.sqlite3") as db:
        binding = json.loads(db.execute("SELECT data FROM identity WHERE id=1").fetchone()[0])
    store = DeviceStore(root, **binding, max_artifact_bytes=max_bytes)
    try:
        if not observed:
            verify_signature(trust, claim.manifest, claim.signature)
        else:
            recorded = store.db.execute(
                "SELECT claim FROM jobs WHERE id=?", (str(claim.job.id),)
            ).fetchone()
            expected = dict(
                manifest=claim.manifest.model_dump(mode="json"),
                signature=claim.signature,
                claim_token=str(claim.claim_token),
                install_challenge=str(claim.install_challenge),
            )
            if recorded is None or json.loads(recorded[0]) != expected:
                raise ValueError("Observation must bind the existing persisted claim")
        if observed:
            current = store.active()
            if current is None:
                raise ValueError("No observed active bank")
        else:
            row = store.db.execute(
                (
                    "SELECT b.* FROM banks b JOIN boots t ON b.name=t.bank WHERE "
                    "t.job_id=? AND b.job_id=? AND b.state='pending_boot'"
                ),
                (str(claim.job.id), str(claim.job.id)),
            ).fetchone()
            if row is None:
                raise ValueError("Candidate bank was not staged")
            current = dict(row)
            current["bank"] = current["name"]
        if store.image_digest(current["sha256"]) != current["sha256"]:
            raise ValueError("Boot image corrupt")
        with (root / "images" / (str(current["sha256"]) + ".bin")).open("rb") as stream:
            if fail_health or stream.read(7) != b"CVOTA1\n":
                raise ValueError("Simulated boot health failed")
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Independent ECU key required")
        if claim.install_challenge is None:
            raise ValueError("Boot challenge required")
        proof = InstallationProof.model_validate(
            dict(
                boot_process_id=os.getpid(),
                tenant_id=binding["tenant"],
                vehicle_id=binding["vehicle"],
                ecu_id=binding["ecu"],
                device_id=binding["device"],
                job_id=claim.job.id,
                claim_token=claim.claim_token,
                challenge=claim.install_challenge,
                sha256=current["sha256"],
                firmware_version=current["version"],
                security_version=current["security_version"],
                bank=current["bank"],
                boot_id=uuid4(),
                boot_confirmed=True,
                booted_at=datetime.now(UTC),
                signature=base64.b64encode(bytes(64)).decode(),
            )
        )
        return proof.model_copy(
            update={"signature": base64.b64encode(key.sign(proof.canonical())).decode()}
        )
    finally:
        store.close()


def probe(
    root: Path,
    claim: ClaimResult,
    key_file: Path,
    trust: Path,
    *,
    observed: bool = False,
    fail_health: bool = False,
    max_bytes: int = 32 * 1024**2,
) -> InstallationProof:
    with exclusive(root) if observed else nullcontext():
        return _probe(
            root,
            claim,
            key_file,
            trust,
            observed=observed,
            fail_health=fail_health,
            max_bytes=max_bytes,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--claim", type=Path, required=True)
    parser.add_argument("--ecu-private-key", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    parser.add_argument("--observed-active", action="store_true")
    parser.add_argument("--fail-health-check", action="store_true")
    parser.add_argument("--max-artifact-bytes", type=int, default=32 * 1024**2)
    args = parser.parse_args()
    try:
        result = probe(
            args.state_dir,
            ClaimResult.model_validate_json(args.claim.read_bytes()),
            args.ecu_private_key,
            args.trusted_keys,
            observed=args.observed_active,
            fail_health=args.fail_health_check,
            max_bytes=args.max_artifact_bytes,
        )
        print(result.model_dump_json())
    except (OSError, ValueError, sqlite3.Error):
        raise SystemExit(2) from None
