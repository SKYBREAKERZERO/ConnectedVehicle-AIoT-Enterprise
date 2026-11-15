"""Cross-module faults: real PostgreSQL rollback plus durable simulated ECU boot.

Initial artifact verification is a trusted fixture; S3/pinned artifact delivery remains
covered by Day18. Runtime reports use real Ed25519 keys and the production transition.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.ota.artifacts import ArtifactVerifier, verify_signature
from connected_vehicle.ota.execution_contracts import (
    ClaimRequest,
    InstallationProof,
    OTAReport,
    SignedManifest,
)
from connected_vehicle.ota.execution_service import OTAExecutionService
from connected_vehicle.ota.service import fingerprint
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.session import create_session_factory
from simulators.ota_device.store import DeviceStore
from tests.integration.day21.conftest import World
from tests.ota_support import registry

pytestmark = pytest.mark.integration


async def audit_fault(world: World, enabled: bool) -> None:
    async with world.admin.begin() as c:
        if enabled:
            await c.execute(
                text("""CREATE OR REPLACE FUNCTION public.day35_fail_audit()
            RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.tenant_id = TG_ARGV[0] THEN RAISE EXCEPTION 'day35 audit interruption';
            END IF; RETURN NEW; END $$""")
            )
            # Tenant is a generated fixture identifier, never external input.
            assert world.tenant.replace("-", "").isalnum()
            await c.execute(
                text(
                    f"CREATE TRIGGER day35_fault BEFORE INSERT ON ota_audit_events "
                    f"FOR EACH ROW EXECUTE FUNCTION day35_fail_audit('{world.tenant}')"
                )
            )
        else:
            await c.execute(text("DROP TRIGGER IF EXISTS day35_fault ON ota_audit_events"))
            await c.execute(text("DROP FUNCTION IF EXISTS public.day35_fail_audit()"))


async def test_wave_job_audit_rollback_then_replay_preserves_single_effect(world: World) -> None:
    campaign = await world.campaign()
    operation = str(uuid4())
    await audit_fault(world, True)
    try:
        with pytest.raises(DBAPIError, match="day35 audit interruption"):
            await world.tick(campaign, operation)
        assert await world.count("ota_jobs") == 0
        assert await world.count("ota_audit_events") == 0
        view = await world.service.get(world.tenant, campaign)
        assert view.job_count == 0 and view.current_wave == -1
    finally:
        await audit_fault(world, False)
    # New service/session instances reconcile the database, not a saved response.
    from connected_vehicle.ota.campaign_service import CampaignService
    from connected_vehicle.ota.service import OTAService

    fresh = CampaignService(
        OTAService(create_session_factory(world.runtime)), ArtifactVerifier(world.settings)
    )
    for _ in range(2):
        result = await fresh.command(
            world.tenant,
            "day21-test",
            campaign,
            "tick",
            operation,
            {"publisher_valid": True},
            "Day21 drill",
        )
        assert result.job_count == 1 and result.current_wave == 0
    assert await world.count("ota_jobs") == 1
    assert await world.count("ota_audit_events") == 1
    async with world.admin.connect() as c:
        assert (
            await c.scalar(
                text("SELECT count(*) FROM ota_campaign_targets WHERE tenant_id=:t AND dispatched"),
                {"t": world.tenant},
            )
            == 1
        )
        assert (
            await c.scalar(
                text(
                    "SELECT count(DISTINCT wave) FROM ota_campaign_targets "
                    "WHERE tenant_id=:t AND dispatched"
                ),
                {"t": world.tenant},
            )
            == 1
        )
        assert await c.scalar(
            text("SELECT count(*) FROM ecu_inventory WHERE tenant_id=:t AND security_version=0"),
            {"t": world.tenant},
        ) == len(world.ecus)


async def test_confirmed_boot_audit_failure_reconciles_without_second_install(
    world: World, tmp_path: Path
) -> None:
    data = b"CVOTA1\nDay35 candidate image"
    checksum = hashlib.sha256(data).hexdigest()
    publisher, ecu_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    trust = tmp_path / "publisher.json"
    trust.write_text(
        json.dumps(
            registry(
                world.tenant,
                "publisher",
                publisher.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        )
    )
    async with world.admin.begin() as c:
        await c.execute(
            text("UPDATE firmware_releases SET sha256=:sha,size_bytes=:size WHERE tenant_id=:t"),
            dict(sha=checksum, size=len(data), t=world.tenant),
        )
    manifest = SignedManifest(
        tenant_id=world.tenant,
        release_id=UUID(world.release),
        ecu_type="body",
        hardware_version="hw1",
        version="2.0",
        artifact_bucket="day21-fixture",
        artifact_key="body/2.0/firmware.bin",
        artifact_version="pinned-version",
        sha256=checksum,
        size_bytes=len(data),
        security_version=1,
        key_id="publisher",
    )
    signature = base64.b64encode(publisher.sign(manifest.canonical())).decode()
    campaign = str(uuid4())
    commands: list[tuple[str, dict[str, Any]]] = [
        (
            "create",
            dict(
                name="Day35",
                manifest=manifest.model_dump(mode="json"),
                signature=signature,
                canary_size=1,
                wave_size=1,
                max_failures=0,
                observation_seconds=0,
                wave_timeout_seconds=60,
            ),
        ),
        ("freeze", {"ecu_ids": world.ecus[:1]}),
        ("start", {}),
    ]
    for command, body in commands:
        await world.service.command(
            world.tenant, "day21-test", campaign, command, str(uuid4()), body, "Day35 fixture"
        )
    await world.tick(campaign)
    async with world.admin.connect() as c:
        job = (
            (
                await c.execute(
                    text("SELECT id,vehicle_id,ecu_id FROM ota_jobs WHERE tenant_id=:t"),
                    dict(t=world.tenant),
                )
            )
            .mappings()
            .one()
        )
    jid, vehicle, ecu = str(job["id"]), str(job["vehicle_id"]), str(job["ecu_id"])
    devices = tmp_path / "devices.json"
    devices.write_text(
        json.dumps(
            {
                world.tenant: {
                    "device": {
                        ecu: dict(
                            vehicle_id=vehicle,
                            install_allowed=True,
                            public_key=base64.b64encode(
                                ecu_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                            ).decode(),
                        )
                    }
                }
            }
        )
    )
    key_file = tmp_path / "ecu.pem"
    key_file.write_bytes(ecu_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    settings = world.settings.model_copy(
        update={"ota_trusted_keys_file": str(trust), "ota_device_keys_file": str(devices)}
    )
    service = OTAExecutionService(create_session_factory(world.runtime), ArtifactVerifier(settings))
    verify_signature(trust, manifest, signature)
    # Trusted initial verified fixture; fault injection starts after this boundary.
    async with service.base.transaction(world.tenant) as session:
        row = await service.job(session, world.tenant, jid)
        await service.transition(
            session,
            row,
            manifest,
            signature,
            "verify",
            "fixture",
            str(uuid4()),
            {"verified_fixture": True},
        )
    claim = await service.claim(
        world.tenant, "device", vehicle, ecu, jid, ClaimRequest(operation_id=uuid4())
    )
    root = tmp_path / "device"
    factory = tmp_path / "factory.bin"
    factory.write_bytes(b"CVOTA1\nfactory")
    root.mkdir()
    store = DeviceStore(
        root,
        tenant=world.tenant,
        vehicle=vehicle,
        ecu=ecu,
        device="device",
        ecu_type="body",
        hardware_version="hw1",
    )
    try:
        store.bootstrap(factory, hashlib.sha256(factory.read_bytes()).hexdigest(), "1.0", 0)
        store.prepare(jid)
        store.accept(claim)
        (root / "images" / (checksum + ".bin")).write_bytes(data)
        store.downloaded(jid)
        store.installing(claim)
        event, payload = store.pending(jid)[0]
        await service.report(
            world.tenant, "device", vehicle, ecu, jid, OTAReport.model_validate_json(payload)
        )
        store.delivered(event)
        store.stage(claim)
        claim_file = tmp_path / "claim.json"
        claim_file.write_text(claim.model_dump_json(), encoding="utf-8")
        boot = await asyncio.to_thread(
            subprocess.run,
            [
                sys.executable,
                "-m",
                "simulators.ota_device.boot_probe",
                "--state-dir",
                str(root),
                "--claim",
                str(claim_file),
                "--ecu-private-key",
                str(key_file),
                "--trusted-keys",
                str(trust),
            ],
            capture_output=True,
            timeout=20,
        )
        assert boot.returncode == 0, boot.stderr.decode()
        proof = InstallationProof.model_validate_json(boot.stdout)
        assert proof.boot_process_id != os.getpid()
        store.activate(claim, healthy=True, proof=proof)
        _, payload = store.pending(jid)[0]
        terminal = OTAReport.model_validate_json(payload)
        before = await world.count("ota_audit_events")
        await audit_fault(world, True)
        try:
            with pytest.raises(DBAPIError, match="day35 audit interruption"):
                await service.report(world.tenant, "device", vehicle, ecu, jid, terminal)
            assert (await service.read(world.tenant, jid)).status == "installing"
            assert (await service.inventory(world.tenant, vehicle, ecu)).security_version == 0
            assert await world.count("ota_audit_events") == before
            async with world.admin.connect() as c:
                assert (
                    await c.scalar(
                        text("SELECT count(*) FROM ota_execution_reports WHERE tenant_id=:t"),
                        dict(t=world.tenant),
                    )
                    == 1
                )
        finally:
            await audit_fault(world, False)
        store.close()
        # Simulate a device/service restart: reopen durable bank/outbox and DB sessions.
        store = DeviceStore(
            root,
            tenant=world.tenant,
            vehicle=vehicle,
            ecu=ecu,
            device="device",
            ecu_type="body",
            hardware_version="hw1",
        )
        persisted = store.pending(jid)
        assert len(persisted) == 1
        terminal = OTAReport.model_validate_json(persisted[0][1])
        assert terminal.installation_proof is not None
        proof = terminal.installation_proof
        engine = create_database_engine(settings)
        try:
            fresh = OTAExecutionService(create_session_factory(engine), ArtifactVerifier(settings))
            for _ in range(2):
                assert (
                    await fresh.report(world.tenant, "device", vehicle, ecu, jid, terminal)
                ).status == "succeeded"
            inventory = await fresh.inventory(world.tenant, vehicle, ecu)
            assert inventory.firmware_version == "2.0" and inventory.security_version == 1
        finally:
            await engine.dispose()
        assert await world.count("ota_audit_events") == before + 1
        active = store.active()
        assert active is not None
        assert (
            active["bank"] == proof.bank
            and active["sha256"] == proof.sha256
            and active["installations"] == 1
        )
        async with world.admin.connect() as c:
            saved: Any = (
                await c.execute(
                    text(
                        "SELECT payload FROM ota_execution_reports "
                        "WHERE tenant_id=:t AND sequence=2"
                    ),
                    dict(t=world.tenant),
                )
            ).scalar_one()
            audit = (
                (
                    await c.execute(
                        text(
                            "SELECT resource_id,actor_id,payload_sha256 FROM ota_audit_events "
                            "WHERE tenant_id=:t AND action='report' AND operation_key=:op"
                        ),
                        dict(t=world.tenant, op=str(terminal.event_id)),
                    )
                )
                .mappings()
                .one()
            )
            assert audit["resource_id"] == jid and audit["actor_id"] == "device"
            assert audit["payload_sha256"] == fingerprint(terminal.model_dump(mode="json"))
            execution = (
                (
                    await c.execute(
                        text(
                            "SELECT claim_token,report_sequence FROM ota_executions "
                            "WHERE tenant_id=:t AND id=:job"
                        ),
                        dict(t=world.tenant, job=jid),
                    )
                )
                .mappings()
                .one()
            )
            assert execution["claim_token"] == str(claim.claim_token)
            assert execution["report_sequence"] == 2
            assert terminal.installation_proof is not None
            assert saved["installation_proof"] == terminal.installation_proof.model_dump(
                mode="json"
            )
        assert (await world.tick(campaign)).status == "completed"
        assert await world.count("ota_jobs") == 1
    finally:
        store.close()
