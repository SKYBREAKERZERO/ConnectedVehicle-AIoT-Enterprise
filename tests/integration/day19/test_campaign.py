"""Real restricted API, dispatcher processes and signed device installations."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3
import httpx2 as httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.ota.contracts import ECURegistration, FirmwareRegistration
from connected_vehicle.ota.execution_contracts import SignedManifest
from connected_vehicle.ota.publisher_keys import records
from connected_vehicle.ota.service import OTAService
from database.ota_operations import operate
from database.provision_ota_authority import provision
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from enterprise_platform.database.session import create_session_factory
from scripts.day16_evidence import provenance
from scripts.day17_release import write_json
from tests.e2e.test_independent_runtimes import ROOT, free_port
from tests.integration.day12.test_credential_cloud_contracts import prepare
from tests.ota_support import registry

if sys.platform == "win32":
    PROCESS_FLAGS = subprocess.CREATE_NEW_PROCESS_GROUP
    STOP_SIGNAL = signal.CTRL_BREAK_EVENT
else:
    PROCESS_FLAGS = 0
    STOP_SIGNAL = signal.SIGTERM


@pytest.mark.integration
async def test_campaign_real_process_rollout_isolation_gates_and_recovery(
    local_environment: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    if "DAY16_EVIDENCE_RUN_ID" not in os.environ:
        monkeypatch.setenv("DAY16_EVIDENCE_RUN_ID", "day19-" + uuid4().hex)
        monkeypatch.setenv("RUNTIME_EVIDENCE_DIR", str(tmp_path / "evidence"))
    tenant = "day19-a"
    _, _, settings, _ = await prepare(local_environment, tenant)
    _, _, foreign_settings, _ = await prepare(local_environment, "day19-b")
    admin = create_database_engine(local_environment)
    runtime = create_database_engine(await load_runtime_database_settings(settings, "application"))
    foreign = create_database_engine(
        await load_runtime_database_settings(foreign_settings, "application")
    )
    base = OTAService(create_session_factory(runtime))
    checks: dict[str, bool] = {}
    publisher = ed25519.Ed25519PrivateKey.generate()
    trust = tmp_path / "publisher.json"
    trust.write_text(
        json.dumps(
            registry(
                tenant,
                "publisher-1",
                publisher.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        ),
        encoding="utf-8",
    )
    receipt = tmp_path / "authority.json"
    receipt.write_text(
        json.dumps(
            {
                tenant: dict(
                    key_id="campaign-authority-1",
                    secret=base64.b64encode(secrets.token_bytes(32)).decode(),
                )
            }
        ),
        encoding="utf-8",
    )
    await provision(local_environment, tenant, receipt)
    await operate(
        local_environment,
        "publisher-register",
        tenant,
        str(uuid4()),
        "key-operator",
        "approved publisher",
        {"keys": records(trust, tenant)},
    )
    factory = tmp_path / "factory.bin"
    factory.write_bytes(b"CVOTA1\ntrusted factory bank")
    factory_sha = hashlib.sha256(factory.read_bytes()).hexdigest()
    data = b"CVOTA1\nDay19 signed candidate firmware"
    s3: Any = boto3.client(
        "s3",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    bucket = "day19-" + uuid4().hex
    await asyncio.to_thread(
        s3.create_bucket,
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": settings.aws_region},
    )
    await asyncio.to_thread(
        s3.put_bucket_versioning, Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )
    await asyncio.to_thread(
        s3.put_public_access_block,
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    await asyncio.to_thread(
        s3.put_bucket_encryption,
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    version = (await asyncio.to_thread(s3.put_object, Bucket=bucket, Key="body.bin", Body=data))[
        "VersionId"
    ]
    release = (
        await base.register_firmware(
            tenant,
            "operator",
            "day19-release",
            FirmwareRegistration(
                ecu_type="body",
                hardware_version="hw-1",
                version="2.0",
                artifact_bucket=bucket,
                artifact_key="body.bin",
                artifact_version=version,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
            ),
        )
    ).release
    manifest = SignedManifest(
        tenant_id=tenant,
        release_id=release.id,
        **release.model_dump(exclude={"id", "created_at", "created_by", "verification_status"}),
        security_version=1,
        key_id="publisher-1",
    )
    signature = base64.b64encode(publisher.sign(manifest.canonical())).decode()
    ecus = sorted(str(uuid4()) for _ in range(9))
    vehicles = {ecu: str(uuid4()) for ecu in ecus}
    ecu_keys = {ecu: ed25519.Ed25519PrivateKey.generate() for ecu in ecus}
    devices = {ecu: "device-" + str(i) for i, ecu in enumerate(ecus)}
    device_registry = tmp_path / "ecu-public.json"
    device_registry.write_text(
        json.dumps(
            {
                tenant: {
                    devices[ecu]: {
                        ecu: dict(
                            vehicle_id=vehicles[ecu],
                            install_allowed=True,
                            public_key=base64.b64encode(
                                ecu_keys[ecu]
                                .public_key()
                                .public_bytes(Encoding.Raw, PublicFormat.Raw)
                            ).decode(),
                        )
                    }
                    for ecu in ecus
                }
            }
        ),
        encoding="utf-8",
    )
    actor_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    actor_public = tmp_path / "oidc-public.pem"
    actor_public.write_bytes(
        actor_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    def bearer(ecu: str | None = None, owner: str = tenant) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = dict(
            iss="https://day19.identity.example",
            aud="vehicle-api",
            sub=devices[ecu] if ecu else "campaign-operator",
            iat=now - timedelta(seconds=5),
            exp=now + timedelta(minutes=20),
            tenant_id=owner,
            principal_type="device" if ecu else "user",
            scope="ota:execute" if ecu else "ota:read ota:manage",
        )
        if ecu:
            claims["vehicle_id"] = vehicles[ecu]
        return jwt.encode(claims, actor_key, algorithm="RS256")

    port = free_port()
    environment = {
        k: v for k, v in os.environ.items() if not k.startswith(("OIDC_", "API_SERVICE_"))
    }
    environment.update(
        PYTHONPATH=str(ROOT),
        APP_ENV="local",
        CLOUD_RUNTIME="localstack",
        APP_HOST="127.0.0.1",
        APP_PORT=str(port),
        AWS_ENDPOINT_URL=str(settings.aws_endpoint_url),
        AWS_REGION=settings.aws_region,
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_CONFIG_FILE=str(tmp_path / "no-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(tmp_path / "no-creds"),
        DATABASE_TENANT_ID=tenant,
        APPLICATION_DATABASE_SECRET_ID=str(settings.application_database_secret_id),
        TRACING_ENABLED="false",
        METRICS_TOKEN=uuid4().hex * 2,
        OTA_TRUSTED_KEYS_FILE=str(trust),
        OTA_INSTALL_RECEIPT_KEYS_FILE=str(receipt),
        OTA_DEVICE_KEYS_FILE=str(device_registry),
        OIDC_ISSUER="https://day19.identity.example",
        OIDC_AUDIENCE="vehicle-api",
        OIDC_PUBLIC_KEY_FILE=str(actor_public),
    )
    log = (tmp_path / "api.log").open("wb")
    server: subprocess.Popen[bytes] | None = None
    try:
        await verify_runtime_database_security(runtime, "application", tenant_id=tenant)
        for ecu in ecus:
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO vehicles "
                        "(tenant_id,id,vin,status,created_at,updated_at) "
                        "VALUES(:t,:v,:vin,'active',now(),now())"
                    ),
                    dict(t=tenant, v=vehicles[ecu], vin=uuid4().hex[:17].upper()),
                )
            await base.register_ecu(
                tenant,
                "inventory-operator",
                vehicles[ecu],
                ecu,
                ECURegistration(
                    ecu_type="body",
                    hardware_version="hw-1",
                    firmware_version="1.0",
                    serial_number=ecu,
                ),
            )
            await operate(
                local_environment,
                "bootstrap",
                tenant,
                str(uuid4()),
                "factory-operator",
                "observed factory bank",
                dict(
                    vehicle_id=vehicles[ecu],
                    ecu_id=ecu,
                    firmware_version="1.0",
                    security_version=0,
                    sha256=factory_sha,
                ),
            )
            (tmp_path / (ecu + ".pem")).write_bytes(
                ecu_keys[ecu].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            (tmp_path / (ecu + ".jwt")).write_text(bearer(ecu), encoding="utf-8")
        server = subprocess.Popen(
            [sys.executable, "-m", "apps.api"],
            cwd=tmp_path,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=PROCESS_FLAGS,
        )
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=40, trust_env=False
        ) as client:
            deadline = time.monotonic() + 40
            while True:
                assert server.poll() is None, (tmp_path / "api.log").read_text(errors="replace")[
                    -2000:
                ]
                try:
                    if (await client.get("/health/ready")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                assert time.monotonic() < deadline, "Campaign API startup deadline"
                await asyncio.sleep(0.1)

            async def api(
                method: str,
                path: str,
                body: Any = None,
                expected: int = 200,
                token: str | None = None,
                key: str | None = None,
            ) -> Any:
                headers = {"Authorization": "Bearer " + (token or bearer())}
                if key:
                    headers["Idempotency-Key"] = key
                response = await client.request(
                    method,
                    path,
                    json=body,
                    headers=headers,
                )
                assert response.status_code == expected, response.text
                return response.json() if expected < 500 else None

            async def create(
                name: str,
                targets: list[str],
                *,
                freeze: bool = True,
                observation: int = 0,
                timeout: int = 900,
            ) -> tuple[str, dict[str, Any]]:
                body = dict(
                    operation_id=str(uuid4()),
                    name=name,
                    release_id=str(release.id),
                    key_id="publisher-1",
                    signature=signature,
                    security_version=1,
                    canary_size=1,
                    wave_size=2,
                    observation_seconds=observation,
                    wave_timeout_seconds=timeout,
                )
                results = await asyncio.gather(
                    *(api("POST", "/v2/ota/campaigns", body, 201) for _ in range(2))
                )
                assert results[0] == results[1]
                campaign = results[0]["id"]
                await api("POST", "/v2/ota/campaigns", body | {"name": "conflict"}, 409)
                frozen = dict(operation_id=str(uuid4()), ecu_ids=targets)
                if freeze:
                    snapshots = await asyncio.gather(
                        *(
                            api("POST", f"/v2/ota/campaigns/{campaign}/freeze", frozen)
                            for _ in range(2)
                        )
                    )
                    assert snapshots[0] == snapshots[1]
                    assert snapshots[0]["target_count"] == len(targets)
                    assert len(snapshots[0]["snapshot_sha256"]) == 64
                return campaign, frozen

            async def action(campaign: str, verb: str, expected: int = 200) -> Any:
                return await api(
                    "POST",
                    f"/v2/ota/campaigns/{campaign}/actions/{verb}",
                    dict(operation_id=str(uuid4()), reason="controlled test operation"),
                    expected,
                )

            async def targets(campaign: str) -> list[dict[str, Any]]:
                result: list[dict[str, Any]] = await api(
                    "GET", f"/v2/ota/campaigns/{campaign}/targets"
                )
                return result

            async def dispatch(campaign: str, *extra: str, expected: int = 0) -> None:
                result = await asyncio.to_thread(
                    subprocess.run,
                    [
                        sys.executable,
                        "-m",
                        "apps.campaign",
                        "--campaign",
                        campaign,
                        "--once",
                        *extra,
                    ],
                    cwd=tmp_path,
                    env=environment,
                    capture_output=True,
                    timeout=90,
                )
                assert result.returncode == expected, result.stderr.decode(errors="replace")[-2500:]

            async def device(target: dict[str, Any], *extra: str, expected: int = 0) -> None:
                ecu = target["ecu_id"]
                result = await asyncio.to_thread(
                    subprocess.run,
                    [
                        sys.executable,
                        "-m",
                        "simulators.ota_device",
                        "--base-url",
                        str(client.base_url).rstrip("/"),
                        "--tenant",
                        tenant,
                        "--vehicle",
                        vehicles[ecu],
                        "--ecu",
                        ecu,
                        "--device-id",
                        devices[ecu],
                        "--ecu-type",
                        "body",
                        "--hardware-version",
                        "hw-1",
                        "--job",
                        target["job_id"],
                        "--state-dir",
                        str(tmp_path / ("device-" + ecu)),
                        "--token-file",
                        str(tmp_path / (ecu + ".jwt")),
                        "--trusted-keys",
                        str(trust),
                        "--ecu-private-key",
                        str(tmp_path / (ecu + ".pem")),
                        "--bootstrap-image",
                        str(factory),
                        "--bootstrap-sha256",
                        factory_sha,
                        "--bootstrap-version",
                        "1.0",
                        "--bootstrap-security-version",
                        "0",
                        *extra,
                    ],
                    cwd=tmp_path,
                    env=environment,
                    capture_output=True,
                    timeout=60,
                )
                assert result.returncode == expected, result.stderr.decode(errors="replace")[-2500:]

            happy, frozen = await create("three ECU rollout", ecus[:3], observation=120)
            checks["create_freeze_idempotent_conflicts_rejected"] = True
            snapshot = await targets(happy)
            await api(
                "POST",
                f"/vehicles/{vehicles[ecus[1]]}/ecus/{ecus[1]}/ota-jobs",
                dict(release_id=str(release.id)),
                409,
                key="reserved-bypass",
            )
            await api(
                "POST",
                f"/v2/ota/campaigns/{happy}/freeze",
                dict(operation_id=str(uuid4()), ecu_ids=ecus[:4]),
                409,
            )
            assert await targets(happy) == snapshot
            checks["immutable_target_snapshot_and_wave_assignment"] = True
            await api(
                "GET", f"/v2/ota/campaigns/{happy}", expected=404, token=bearer(owner="day19-b")
            )
            await api(
                "POST",
                "/v2/ota/campaigns",
                dict(
                    operation_id=str(uuid4()),
                    name="device denied",
                    release_id=str(release.id),
                    key_id="publisher-1",
                    signature=signature,
                    security_version=1,
                    canary_size=1,
                    wave_size=1,
                ),
                403,
                token=bearer(ecus[0]),
            )
            for table in ("ota_campaigns", "ota_campaign_targets", "ota_campaign_events"):
                async with foreign.begin() as connection:
                    await connection.execute(
                        text("SELECT set_config('app.tenant_id',:t,true)"), dict(t=tenant)
                    )
                    assert await connection.scalar(text(f"SELECT count(*) FROM {table}")) == 0
                for sql in (f"DELETE FROM {table}", f"INSERT INTO {table} DEFAULT VALUES"):
                    with pytest.raises(DBAPIError):
                        async with runtime.begin() as connection:
                            await connection.execute(text(sql))
            with pytest.raises(DBAPIError):
                async with runtime.begin() as connection:
                    await connection.execute(
                        text("SELECT ota_campaign_command('{}',:mac)"), dict(mac="0" * 64)
                    )
            async with admin.begin() as connection:
                # Model an already provisioned shared runtime with normal public-schema access.
                await connection.execute(text("GRANT USAGE ON SCHEMA public TO app_user"))
                await connection.execute(text("SET LOCAL ROLE app_user"))
                await connection.execute(
                    text("SELECT set_config('app.tenant_id',:t,true)"), dict(t=tenant)
                )
                for table in ("ota_campaigns", "ota_campaign_targets", "ota_campaign_events"):
                    assert await connection.scalar(text(f"SELECT count(*) FROM {table}")) == 0
            checks["shared_login_cannot_select_campaign_tenant"] = True
            checks["fixed_login_rls_and_runtime_writes_denied"] = True
            await action(happy, "start")
            await dispatch(happy, "--crash-after-jobs", expected=91)
            after_crash = await targets(happy)
            assert sum(t["dispatched"] for t in after_crash) == 1
            assert after_crash[0]["job_status"] == "pending_verification"
            await asyncio.gather(dispatch(happy), dispatch(happy))
            recovered = await targets(happy)
            assert [t["job_id"] for t in recovered] == [t["job_id"] for t in snapshot]
            assert recovered[0]["job_status"] == "verified"
            assert all(t["job_status"] is None for t in recovered[1:])
            checks["dispatcher_crash_concurrency_single_job_per_target"] = True
            await dispatch(happy)
            assert (await api("GET", f"/v2/ota/campaigns/{happy}"))["current_wave"] == 0
            await device(recovered[0])
            await dispatch(happy)
            assert (await api("GET", f"/v2/ota/campaigns/{happy}"))["current_wave"] == 0
            assert sum(t["dispatched"] for t in await targets(happy)) == 1

            # Controlled wall-clock fault: age only the committed gate timestamp, not results.
            async def elapse_observation() -> None:
                async with admin.begin() as connection:
                    await connection.execute(
                        text(
                            "UPDATE ota_jobs j SET updated_at=updated_at-"
                            "interval '121 seconds' FROM ota_campaign_targets t WHERE "
                            "t.tenant_id=j.tenant_id AND t.job_id=j.id AND t.campaign_id=:c"
                        ),
                        dict(c=happy),
                    )

            await elapse_observation()
            checks["observation_window_blocks_early_promotion"] = True
            await asyncio.gather(dispatch(happy), dispatch(happy))
            wave = await targets(happy)
            assert all(t["job_status"] == "verified" for t in wave[1:])
            await asyncio.gather(*(device(t) for t in wave[1:]))
            await elapse_observation()
            await dispatch(happy)
            result = await api("GET", f"/v2/ota/campaigns/{happy}")
            assert (
                result["status"] == "completed"
                and result["succeeded"] == 3
                and result["failed"] == 0
            )
            async with admin.connect() as connection:
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM ecu_inventory "
                            "WHERE tenant_id=:t AND security_version=1"
                        ),
                        dict(t=tenant),
                    )
                    == 3
                )
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ota_execution_reports WHERE tenant_id=:t"),
                        dict(t=tenant),
                    )
                    == 6
                )
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM ota_audit_events a "
                            "JOIN ota_campaign_targets t ON t.tenant_id=a.tenant_id "
                            "AND t.job_id=a.resource_id "
                            "WHERE t.campaign_id=:c AND a.action='report'"
                        ),
                        dict(c=happy),
                    )
                    == 6
                )
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM ota_audit_events a "
                            "JOIN ota_campaign_targets t ON t.tenant_id=a.tenant_id "
                            "AND t.job_id=a.resource_id "
                            "WHERE t.campaign_id=:c AND a.action='create'"
                        ),
                        dict(c=happy),
                    )
                    == 3
                )
            checks["canary_success_releases_wave_and_real_devices_complete"] = True
            checks["inventory_reports_audit_and_snapshot_agree"] = True
            shutdown = subprocess.Popen(
                [sys.executable, "-m", "apps.campaign", "--campaign", happy, "--interval", "1"],
                cwd=tmp_path,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=PROCESS_FLAGS,
            )
            try:
                assert shutdown.stdout is not None
                line = await asyncio.wait_for(asyncio.to_thread(shutdown.stdout.readline), 15)
                assert json.loads(line)["status"] == "completed"
                shutdown.send_signal(STOP_SIGNAL)
                assert await asyncio.to_thread(shutdown.wait, timeout=15) == 0
            finally:
                if shutdown.poll() is None:
                    shutdown.kill()
                    await asyncio.to_thread(shutdown.wait, timeout=5)
                if shutdown.stdout:
                    shutdown.stdout.close()
                if shutdown.stderr:
                    shutdown.stderr.close()
            checks["graceful_shutdown_stops_dispatch_and_closes_pool"] = True

            failure, freeze_request = await create("failed canary", ecus[3:6], freeze=False)
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "CREATE FUNCTION public.day19_fail_audit() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                        "'injected campaign audit fault'; END $$"
                    )
                )
                await connection.execute(
                    text(
                        "CREATE TRIGGER day19_fail_audit BEFORE INSERT ON "
                        "ota_campaign_events FOR EACH ROW EXECUTE FUNCTION "
                        "public.day19_fail_audit()"
                    )
                )
            try:
                await api("POST", f"/v2/ota/campaigns/{failure}/freeze", freeze_request, 500)
                assert (await api("GET", f"/v2/ota/campaigns/{failure}"))["status"] == "draft"
                assert await targets(failure) == []
            finally:
                async with admin.begin() as connection:
                    await connection.execute(
                        text("DROP TRIGGER day19_fail_audit ON ota_campaign_events")
                    )
                    await connection.execute(text("DROP FUNCTION public.day19_fail_audit()"))
            await api("POST", f"/v2/ota/campaigns/{failure}/freeze", freeze_request)
            await api("POST", f"/v2/ota/campaigns/{failure}/freeze", freeze_request)
            checks["audit_failure_rolls_back_snapshot_and_retry_is_safe"] = True
            await action(failure, "start")
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "CREATE FUNCTION public.day19_fail_wave() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                        "'injected wave audit fault'; END $$"
                    )
                )
                await connection.execute(
                    text(
                        "CREATE TRIGGER day19_fail_wave BEFORE INSERT ON "
                        "ota_campaign_events FOR EACH ROW WHEN (NEW.request->>'command'='tick') "
                        "EXECUTE FUNCTION public.day19_fail_wave()"
                    )
                )
            try:
                await dispatch(failure, expected=1)
                rolled_back = await api("GET", f"/v2/ota/campaigns/{failure}")
                assert rolled_back["current_wave"] == -1 and rolled_back["job_count"] == 0
                async with admin.connect() as connection:
                    assert (
                        await connection.scalar(
                            text(
                                "SELECT count(*) FROM ota_jobs j "
                                "JOIN ota_campaign_targets t ON t.tenant_id=j.tenant_id "
                                "AND t.job_id=j.id "
                                "WHERE t.campaign_id=:c"
                            ),
                            dict(c=failure),
                        )
                        == 0
                    )
            finally:
                async with admin.begin() as connection:
                    await connection.execute(
                        text("DROP TRIGGER day19_fail_wave ON ota_campaign_events")
                    )
                    await connection.execute(text("DROP FUNCTION public.day19_fail_wave()"))
            checks["wave_job_audit_failure_rolls_back_all_effects"] = True
            await dispatch(failure)
            failed_targets = await targets(failure)
            await device(failed_targets[0], "--fail-health-check")
            await dispatch(failure)
            paused = await api("GET", f"/v2/ota/campaigns/{failure}")
            assert (
                paused["status"] == "paused" and paused["pause_reason"] == "failure_budget_exceeded"
            )
            assert paused["job_count"] == 1 and paused["failed"] == 1
            await action(failure, "resume", 409)
            assert all(t["job_status"] is None for t in (await targets(failure))[1:])
            checks["failed_canary_blocks_later_waves_and_resume"] = True

            inactive, _ = await create("disabled after claim", ecus[6:8])
            await action(inactive, "start")
            await dispatch(inactive)
            inactive_target = (await targets(inactive))[0]
            await device(inactive_target, "--crash-at", "after_download", expected=86)
            async with admin.begin() as connection:
                await connection.execute(
                    text("UPDATE vehicles SET status='suspended' WHERE id=:v"),
                    dict(v=inactive_target["vehicle_id"]),
                )
            await dispatch(inactive)
            assert (await api("GET", f"/v2/ota/campaigns/{inactive}"))["status"] == "paused"
            await device(inactive_target, expected=1)
            async with admin.begin() as connection:
                await connection.execute(
                    text("UPDATE vehicles SET status='active' WHERE id=:v"),
                    dict(v=inactive_target["vehicle_id"]),
                )
            # Pausing rollout must still allow a previously claimed device to report its outcome.
            await device(inactive_target)
            assert (await targets(inactive))[0]["job_status"] == "succeeded"
            await action(inactive, "cancel")
            assert (await targets(inactive))[1]["job_status"] is None
            checks["inactive_vehicle_pauses_and_inflight_result_can_reconcile"] = True

            one, _ = await create("competing rollout one", [ecus[4]])
            two, _ = await create("competing rollout two", [ecus[4]])
            await action(one, "start")
            await action(two, "start")
            await asyncio.gather(dispatch(one), dispatch(two))
            results = [await api("GET", f"/v2/ota/campaigns/{c}") for c in (one, two)]
            assert sum(row["job_count"] for row in results) == 1
            assert sorted(row["status"] for row in results) == ["paused", "running"]
            for campaign in (one, two):
                await action(campaign, "cancel")
                assert all(
                    t["job_status"] in {None, "failed", "cancelled"}
                    for t in await targets(campaign)
                )
            async with admin.connect() as connection:
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM ota_audit_events a "
                            "JOIN ota_campaign_targets t ON t.tenant_id=a.tenant_id "
                            "AND t.job_id=a.resource_id WHERE t.campaign_id IN (:one,:two) "
                            "AND a.action='campaign_cancel'"
                        ),
                        dict(one=one, two=two),
                    )
                    == 1
                )
                assert (
                    await connection.scalar(
                        text(
                            "SELECT security_version FROM ecu_inventory "
                            "WHERE tenant_id=:t AND id=:e"
                        ),
                        dict(t=tenant, e=ecus[4]),
                    )
                    == 0
                )
            checks["competing_campaigns_cannot_duplicate_active_ecu_jobs"] = True
            checks["cancellation_withdraws_unclaimed_jobs_without_faking_execution"] = True

            timed, _ = await create("stalled wave", [ecus[5]], timeout=30)
            await action(timed, "start")
            await dispatch(timed)
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE ota_campaigns SET wave_started_at="
                        "wave_started_at-interval '31 seconds' WHERE id=:c"
                    ),
                    dict(c=timed),
                )
            await dispatch(timed)
            timed_result = await api("GET", f"/v2/ota/campaigns/{timed}")
            assert (
                timed_result["status"] == "paused"
                and timed_result["pause_reason"] == "wave_timeout"
            )
            assert timed_result["succeeded"] == 0 and timed_result["job_count"] == 1
            await action(timed, "cancel")
            checks["stalled_wave_times_out_without_inventing_success"] = True

            revoked, _ = await create("revoked publisher", [ecus[8]])
            await action(revoked, "start")
            await operate(
                local_environment,
                "publisher-revoke",
                tenant,
                str(uuid4()),
                "key-operator",
                "publisher withdrawn",
                dict(key_id="publisher-1"),
            )
            await dispatch(revoked)
            withdrawn = await api("GET", f"/v2/ota/campaigns/{revoked}")
            assert withdrawn["status"] == "paused" and withdrawn["job_count"] == 0
            assert withdrawn["pause_reason"] == "publisher_revoked_or_unavailable"
            checks["publisher_revocation_blocks_dispatch_with_stale_registry"] = True
            # Runtime cannot mutate policy or suppress durable campaign audit.
            for sql in (
                "UPDATE ota_campaigns SET status='running'",
                "UPDATE ota_campaign_targets SET wave=99",
                "DELETE FROM ota_campaign_events",
            ):
                with pytest.raises(DBAPIError):
                    async with runtime.begin() as connection:
                        await connection.execute(text(sql))
            checks["snapshot_and_canary_policy_cannot_be_bypassed_by_db_credentials"] = True
    finally:
        if server and server.poll() is None:
            server.send_signal(STOP_SIGNAL)
            await asyncio.to_thread(server.wait, timeout=15)
        log.close()
        await runtime.dispose()
        await foreign.dispose()
        await admin.dispose()
    from scripts.day19_evidence import source_digest

    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    write_json(
        directory / "day19-campaign.json",
        dict(
            version=1,
            profile="local_drill",
            generated_at_utc=datetime.now(UTC).isoformat(),
            provenance=provenance(),
            day19_sha256=source_digest(),
            checks=checks,
            device_successes=4,
            real_aws_verified=False,
            physical_boot_verified=False,
            simulated_installation=True,
        ),
    )
