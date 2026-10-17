from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from connected_vehicle.ota.artifacts import verify_signature
from connected_vehicle.ota.execution_contracts import (
    ClaimResult,
    ExecutionView,
    OTAState,
    SignedManifest,
)
from simulators.ota_device.boot_probe import probe
from simulators.ota_device.store import DeviceStore, exclusive
from tests.ota_support import registry


def fixture_claim(tmp_path: Path) -> tuple[ClaimResult, Path, bytes]:
    data = b"CVOTA1\nlocal firmware"
    manifest = SignedManifest(
        tenant_id="tenant-a",
        release_id=uuid4(),
        ecu_type="body",
        hardware_version="hw-1",
        version="2.0",
        artifact_bucket="local-firmware",
        artifact_key="image.bin",
        artifact_version="version-1",
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        security_version=1,
        key_id="key-1",
    )
    private = Ed25519PrivateKey.generate()
    signature = base64.b64encode(private.sign(manifest.canonical())).decode()
    trust = tmp_path / "public.json"
    trust.write_text(
        json.dumps(
            registry(
                "tenant-a",
                "key-1",
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        )
    )
    (tmp_path / "ecu.pem").write_bytes(
        private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    job = ExecutionView(
        id=uuid4(),
        vehicle_id=uuid4(),
        ecu_id=uuid4(),
        release_id=manifest.release_id,
        status=OTAState.DOWNLOADING,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by="operator",
    )
    return (
        ClaimResult(
            job=job,
            device_id="device-a",
            claim_token=uuid4(),
            manifest=manifest,
            signature=signature,
            install_challenge=uuid4(),
        ),
        trust,
        data,
    )


def install(store: DeviceStore, claim: ClaimResult, trust: Path) -> None:
    if store.state(str(claim.job.id)) in {"installed", "failed", "reported"}:
        store.activate(claim, healthy=True)
        return
    store.stage(claim)
    proof = probe(store.root, claim, trust.parent / "ecu.pem", trust)
    store.activate(claim, healthy=True, proof=proof)


@pytest.mark.parametrize("change", ["tenant", "bytes", "counter", "key", "signature"])
def test_signed_manifest_cannot_be_retargeted(tmp_path: Path, change: str) -> None:
    claim, trust, _ = fixture_claim(tmp_path)
    verify_signature(trust, claim.manifest, claim.signature)
    modifications: dict[str, object] = {
        "tenant": "tenant-b",
        "bytes": "0" * 64,
        "counter": 2,
        "key": "unknown",
    }
    names = {
        "tenant": "tenant_id",
        "bytes": "sha256",
        "counter": "security_version",
        "key": "key_id",
    }
    manifest = (
        claim.manifest.model_copy(update={names[change]: modifications[change]})
        if change != "signature"
        else claim.manifest
    )
    signature = base64.b64encode(b"0" * 64).decode() if change == "signature" else claim.signature
    with pytest.raises(ValueError):
        verify_signature(trust, manifest, signature)


def test_activation_and_terminal_outbox_survive_restart_without_second_effect(
    tmp_path: Path,
) -> None:
    claim, trust, data = fixture_claim(tmp_path)
    root = tmp_path / "device"
    binding: dict[str, Any] = dict(
        tenant="tenant-a",
        vehicle=str(claim.job.vehicle_id),
        ecu=str(claim.job.ecu_id),
        device="device-a",
        ecu_type="body",
        hardware_version="hw-1",
    )
    with exclusive(root):
        store = DeviceStore(root, **binding)
        store.prepare(str(claim.job.id))
        with pytest.raises(ValueError, match="ownership"):
            store.accept(
                claim.model_copy(
                    update={
                        "manifest": claim.manifest.model_copy(
                            update={"hardware_version": "different-hardware"}
                        )
                    }
                )
            )
        store.accept(claim)
        images = root / "images"
        images.mkdir()
        (images / (claim.manifest.sha256 + ".bin")).write_bytes(data)
        store.downloaded(str(claim.job.id))
        store.installing(claim)
        with pytest.raises(ValueError, match="confirmed"):
            install(store, claim, trust)
        store.delivered(store.pending(str(claim.job.id))[0][0])
        install(store, claim, trust)
        before = store.active()
        pending = store.pending(str(claim.job.id))
        store.close()
    with exclusive(root):
        store = DeviceStore(root, **binding)
        store.accept(claim)
        install(store, claim, trust)
        assert store.active() == before and store.pending(str(claim.job.id)) == pending
        assert before is not None and before["installations"] == 1
        with pytest.raises(ValueError, match="trusted cloud floor"):
            store.accept(
                claim.model_copy(
                    update={
                        "job": claim.job.model_copy(update={"id": uuid4()}),
                        "recorded_security_version": 0,
                        "recorded_firmware_version": "factory-wrong",
                    }
                )
            )
        assert store.active() == before and store.pending(str(claim.job.id)) == pending
        store.close()


def test_persistent_ownership_and_process_lock_are_enforced(tmp_path: Path) -> None:
    claim, _, _ = fixture_claim(tmp_path)
    root = tmp_path / "device"
    binding: dict[str, Any] = dict(
        tenant="tenant-a",
        vehicle=str(claim.job.vehicle_id),
        ecu=str(claim.job.ecu_id),
        device="device-a",
        ecu_type="body",
        hardware_version="hw-1",
    )
    with exclusive(root):
        store = DeviceStore(root, **binding)
        store.close()
        with pytest.raises(OSError), exclusive(root):
            pass
    with pytest.raises(ValueError, match="ownership"):
        DeviceStore(root, **(binding | {"tenant": "tenant-b"}))


def test_local_commit_failure_and_anti_rollback_preserve_active_pointer(tmp_path: Path) -> None:
    claim, trust, data = fixture_claim(tmp_path)
    root = tmp_path / "device"
    with exclusive(root):
        store = DeviceStore(
            root,
            tenant="tenant-a",
            vehicle=str(claim.job.vehicle_id),
            ecu=str(claim.job.ecu_id),
            device="device-a",
            ecu_type="body",
            hardware_version="hw-1",
        )
        job = str(claim.job.id)
        store.prepare(job)
        store.accept(claim)
        images = root / "images"
        images.mkdir()
        (images / (claim.manifest.sha256 + ".bin")).write_bytes(data)
        store.downloaded(job)
        store.installing(claim)
        store.delivered(store.pending(job)[0][0])
        store.db.execute("""CREATE TRIGGER fail_terminal BEFORE INSERT ON reports
            WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'commit fault'); END""")
        with pytest.raises(sqlite3.IntegrityError):
            install(store, claim, trust)
        assert store.active() is None and store.state(job) == "installing"
        assert not store.pending(job)
        store.db.execute("DROP TRIGGER fail_terminal")
        install(store, claim, trust)
        before = store.active()
        replay = claim.model_copy(update={"job": claim.job.model_copy(update={"id": uuid4()})})
        replay_id = str(replay.job.id)
        store.prepare(replay_id)
        store.accept(replay)
        store.downloaded(replay_id)
        store.installing(replay)
        store.delivered(store.pending(replay_id)[0][0])
        with pytest.raises(ValueError, match="anti-rollback"):
            install(store, replay, trust)
        assert store.active() == before
        store.close()
