from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import sqlite3
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

from connected_vehicle.ota.device_proof import proof_headers
from connected_vehicle.ota.execution_contracts import ClaimResult, ExecutionView, SignedManifest
from connected_vehicle.ota.publisher_keys import records as publisher_records
from database.ota_operations import operate
from database.provision_ota_authority import provision
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from scripts.day16_evidence import provenance
from scripts.day17_release import write_json
from scripts.day18_evidence import source_digest
from simulators.ota_device.boot_probe import probe
from simulators.ota_device.store import DeviceStore, exclusive
from tests.e2e.test_independent_runtimes import ROOT, free_port
from tests.integration.day12.test_credential_cloud_contracts import prepare
from tests.integration.day18.http_fault_proxy import HTTPResponseDropProxy
from tests.ota_support import registry


@pytest.mark.integration
async def test_signed_pinned_ota_process_crashes_and_durable_cloud_results(
    local_environment: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    identifier = "day18-" + uuid4().hex
    if "DAY16_EVIDENCE_RUN_ID" not in os.environ:
        monkeypatch.setenv("DAY16_EVIDENCE_RUN_ID", identifier)
        monkeypatch.setenv("RUNTIME_EVIDENCE_DIR", str(ROOT / ".runtime-reports" / identifier))
    _, _, settings, _ = await prepare(local_environment, "day18-a")
    admin = create_database_engine(local_environment)
    vehicle, ecu, other_ecu = str(uuid4()), str(uuid4()), str(uuid4())
    actor_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oidc_key = tmp_path / "oidc-public.pem"
    oidc_key.write_bytes(
        actor_private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    signer = ed25519.Ed25519PrivateKey.generate()
    trust = tmp_path / "ota-public.json"
    trust.write_text(
        json.dumps(
            registry(
                "day18-a",
                "manufacturer-1",
                signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
        )
    )
    await operate(
        local_environment,
        "publisher-register",
        "day18-a",
        str(uuid4()),
        "factory-operator",
        "approved manufacturer key",
        {"keys": publisher_records(trust, "day18-a")},
    )
    factory = tmp_path / "factory.bin"
    factory.write_bytes(b"CVOTA1\nfactory image v1")
    factory_digest = hashlib.sha256(factory.read_bytes()).hexdigest()

    def bearer(
        *,
        device: str | None = None,
        tenant: str = "day18-a",
        scope: str | None = None,
        bound_vehicle: str = vehicle,
        expired: bool = False,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, object] = dict(
            iss="https://day18.identity.example",
            aud="vehicle-api",
            sub=device or "ota-operator",
            iat=now - timedelta(minutes=10),
            exp=now + timedelta(minutes=-1 if expired else 15),
            tenant_id=tenant,
            principal_type="device" if device else "user",
            scope=scope or ("ota:execute" if device else "ota:read ota:manage"),
        )
        if device:
            claims["vehicle_id"] = bound_vehicle
        return jwt.encode(claims, actor_private, algorithm="RS256")

    device_token = tmp_path / "device-token"
    device_token.write_text(bearer(device="tbox-1"))
    device_token.chmod(0o600)
    ecu_key = ed25519.Ed25519PrivateKey.generate()
    ecu_key_path = tmp_path / "ecu-private.pem"
    ecu_key_path.write_bytes(
        ecu_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    ecu_key_path.chmod(0o600)
    ecu_registry = tmp_path / "ecu-registry.json"
    ecu_registry.write_text(
        json.dumps(
            {
                "day18-a": {
                    device: {
                        ecu: {
                            "vehicle_id": vehicle,
                            "install_allowed": True,
                            "public_key": base64.b64encode(
                                ecu_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                            ).decode(),
                        }
                    }
                    for device in ("tbox-1", "other-device")
                }
            }
        )
    )
    receipt_keys = tmp_path / "receipt-keys.json"
    receipt_keys.write_text(
        json.dumps(
            {
                "day18-a": {
                    "key_id": "local-receipt-1",
                    "secret": base64.b64encode(secrets.token_bytes(32)).decode(),
                }
            }
        )
    )
    receipt_keys.chmod(0o600)
    await provision(local_environment, "day18-a", receipt_keys)
    s3: Any = boto3.client(
        "s3",
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    bucket = "day18-" + uuid4().hex
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
    data = b"CVOTA1\n" + b"firmware-v2" * 100
    version = (
        await asyncio.to_thread(s3.put_object, Bucket=bucket, Key="tenant-a/body.bin", Body=data)
    )["VersionId"]
    # The latest object is intentionally different; only the signed historical version is valid.
    await asyncio.to_thread(
        s3.put_object, Bucket=bucket, Key="tenant-a/body.bin", Body=b"corrupt-latest"
    )
    port = free_port()
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OIDC_", "API_SERVICE_"))
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
        DATABASE_TENANT_ID="day18-a",
        APPLICATION_DATABASE_SECRET_ID=str(settings.application_database_secret_id),
        TRACING_ENABLED="false",
        METRICS_TOKEN=uuid4().hex * 2,
        OTA_TRUSTED_KEYS_FILE=str(trust),
        OIDC_ISSUER="https://day18.identity.example",
        OIDC_AUDIENCE="vehicle-api",
        OIDC_PUBLIC_KEY_FILE=str(oidc_key),
        OTA_DEVICE_KEYS_FILE=str(ecu_registry),
        OTA_INSTALL_RECEIPT_KEYS_FILE=str(receipt_keys),
    )
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        flags = 0
    log = (tmp_path / "api.log").open("wb")
    process: subprocess.Popen[bytes] | None = None
    checks: dict[str, bool] = {}
    state_dir = tmp_path / "device-state"
    try:
        async with admin.begin() as connection:
            await connection.execute(
                text("""INSERT INTO vehicles
                (id,vin,tenant_id,status,created_at,updated_at)
                VALUES (:id,:vin,'day18-a','active',now(),now())"""),
                {"id": vehicle, "vin": uuid4().hex[:17].upper()},
            )
        process = subprocess.Popen(
            [sys.executable, "-m", "apps.api"],
            cwd=tmp_path,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=30, trust_env=False
        ) as client:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "Restricted API did not start"
                try:
                    if (await client.get("/health/ready")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise AssertionError("API startup timeout")
                await asyncio.sleep(0.1)

            async def api(
                method: str,
                path: str,
                *,
                expected: int = 200,
                token: str | None = None,
                body: object = None,
                key: str | None = None,
                sign_proof: bool = True,
                extra_headers: dict[str, str] | None = None,
            ) -> dict[str, Any]:
                headers = {"Authorization": "Bearer " + (token or bearer())}
                if key:
                    headers["Idempotency-Key"] = key
                if path.endswith("/artifact"):
                    headers["X-OTA-Claim"] = str(uuid4())
                headers.update(extra_headers or {})
                request = client.build_request(method, path, headers=headers, json=body)
                claims = jwt.decode(token or bearer(), options={"verify_signature": False})
                if (
                    sign_proof
                    and claims.get("principal_type") == "device"
                    and path.startswith("/v2/vehicles/")
                ):
                    request.headers.update(
                        proof_headers(
                            ecu_key,
                            method=method,
                            path=path,
                            body=request.content,
                            tenant=claims["tenant_id"],
                            vehicle=claims["vehicle_id"],
                            ecu=path.split("/")[5],
                            device=claims["sub"],
                            nonce=str(uuid4()),
                            timestamp=str(int(time.time())),
                        )
                    )
                response = await client.send(request)
                assert response.status_code == expected, f"{method} {path}: {response.status_code}"
                return response.json()  # type: ignore[no-any-return]

            for target, serial in ((ecu, "body-1"), (other_ecu, "body-2")):
                await api(
                    "PUT",
                    f"/vehicles/{vehicle}/ecus/{target}",
                    body=dict(
                        ecu_type="body",
                        hardware_version="hw-1",
                        firmware_version="1.0",
                        serial_number=serial,
                    ),
                )

            async def candidate(
                *,
                target: str = ecu,
                version_name: str = "2.0",
                security: int = 1,
                checksum: str = hashlib.sha256(data).hexdigest(),
                publisher: str = "manufacturer-1",
                signing: ed25519.Ed25519PrivateKey | None = None,
            ) -> tuple[str, dict[str, object]]:
                metadata = dict(
                    ecu_type="body",
                    hardware_version="hw-1",
                    version=version_name,
                    artifact_bucket=bucket,
                    artifact_key="tenant-a/body.bin",
                    artifact_version=version,
                    sha256=checksum,
                    size_bytes=len(data),
                )
                release = await api(
                    "POST", "/ota/firmware-releases", body=metadata, key=str(uuid4()), expected=201
                )
                release_id = release["release"]["id"]
                job = await api(
                    "POST",
                    f"/vehicles/{vehicle}/ecus/{target}/ota-jobs",
                    body={"release_id": release_id},
                    key=str(uuid4()),
                    expected=202,
                )
                manifest = SignedManifest(
                    **metadata,
                    tenant_id="day18-a",
                    release_id=release_id,
                    security_version=security,
                    key_id=publisher,
                )
                request: dict[str, object] = dict(
                    operation_id=str(uuid4()),
                    key_id=publisher,
                    security_version=security,
                    signature=base64.b64encode(
                        (signing or signer).sign(manifest.canonical())
                    ).decode(),
                )
                return job["job"]["id"], request

            job, verification = await candidate()
            path = f"/v2/vehicles/{vehicle}/ecus/{ecu}/ota-jobs/{job}"
            await api("POST", f"/v2/ota/jobs/{job}/verify", body=verification, expected=409)
            for target in (ecu, other_ecu):
                await operate(
                    local_environment,
                    "bootstrap",
                    "day18-a",
                    str(uuid4()),
                    "factory-operator",
                    "controlled factory measurement",
                    dict(
                        vehicle_id=vehicle,
                        ecu_id=target,
                        firmware_version="1.0",
                        security_version=0,
                        sha256=factory_digest,
                    ),
                )
            checks["trusted_initial_bootstrap_required"] = True
            before_proofs = await api("GET", f"/v2/ota/jobs/{job}")
            for method, endpoint, payload in (
                ("POST", path + "/claim", {"operation_id": str(uuid4())}),
                ("GET", path + "/artifact", None),
                ("GET", f"/v2/vehicles/{vehicle}/ecus/{ecu}/ota-jobs/next", None),
                (
                    "POST",
                    path + "/reports",
                    dict(
                        event_id=str(uuid4()),
                        claim_token=str(uuid4()),
                        sequence=1,
                        status="installing",
                        occurred_at=datetime.now(UTC).isoformat(),
                    ),
                ),
            ):
                # A valid vehicle JWT alone is no longer installation authority.
                await api(
                    method,
                    endpoint,
                    token=bearer(device="tbox-1"),
                    body=payload,
                    sign_proof=False,
                    expected=403,
                )
            await api(
                "POST",
                path + "/claim",
                token=bearer(device="unregistered-device"),
                body={"operation_id": str(uuid4())},
                expected=403,
            )
            await api(
                "POST",
                f"/v2/vehicles/{vehicle}/ecus/{other_ecu}/ota-jobs/{job}/claim",
                token=bearer(device="tbox-1"),
                body={"operation_id": str(uuid4())},
                expected=403,
            )
            replay_body = json.dumps({"operation_id": str(uuid4())}, separators=(",", ":")).encode()
            replay_headers = {
                "Authorization": "Bearer " + bearer(device="tbox-1"),
                "Content-Type": "application/json",
                **proof_headers(
                    ecu_key,
                    method="POST",
                    path=path + "/claim",
                    body=replay_body,
                    tenant="day18-a",
                    vehicle=vehicle,
                    ecu=ecu,
                    device="tbox-1",
                    nonce=str(uuid4()),
                    timestamp=str(int(time.time())),
                ),
            }
            assert (
                await client.post(path + "/claim", content=replay_body, headers=replay_headers)
            ).status_code == 409
            assert (
                await client.post(path + "/claim", content=replay_body, headers=replay_headers)
            ).status_code == 403
            assert await api("GET", f"/v2/ota/jobs/{job}") == before_proofs
            checks["independent_ecu_proof_and_replay_protection"] = True
            await api(
                "POST",
                path + "/claim",
                token=bearer(device="tbox-1"),
                body={"operation_id": str(uuid4())},
                expected=409,
            )
            checks["unverified_claim_denied"] = True
            await api(
                "POST",
                f"/v2/ota/jobs/{job}/verify",
                body=verification | {"signature": base64.b64encode(b"0" * 64).decode()},
                expected=409,
            )
            checks["untrusted_signature_denied"] = True
            bad, invalid = await candidate(
                target=other_ecu, version_name="bad-bytes", checksum="0" * 64
            )
            await api("POST", f"/v2/ota/jobs/{bad}/verify", body=invalid, expected=409)
            async with admin.connect() as connection:
                assert await connection.scalar(text("SELECT count(*) FROM ota_executions")) == 0
            checks["checksum_failure_no_execution_side_effects"] = True
            await api(
                "POST",
                f"/ota/jobs/{bad}/cancel",
                body={"reason": "invalid artifact"},
                key=str(uuid4()),
            )
            results = await asyncio.gather(
                *(api("POST", f"/v2/ota/jobs/{job}/verify", body=verification) for _ in range(2))
            )
            assert all(row["status"] == "verified" for row in results)
            checks["concurrent_verification_single_transition"] = True
            await api("GET", f"/ota/jobs/{job}", expected=409)
            checks["v1_contract_rejects_opted_in_v2_state"] = True
            await api("GET", f"/v2/ota/jobs/{job}", token=bearer(tenant="day18-b"), expected=404)
            await api("POST", path + "/claim", body={"operation_id": str(uuid4())}, expected=403)
            await api(
                "POST",
                path + "/claim",
                token=bearer(device="tbox-1", bound_vehicle=str(uuid4())),
                body={"operation_id": str(uuid4())},
                expected=403,
            )
            await api(
                "POST",
                f"/v2/ota/jobs/{job}/verify",
                token=bearer(device="tbox-1", scope="ota:manage"),
                body=verification,
                expected=403,
            )
            checks["tenant_vehicle_and_principal_authorization"] = True
            with exclusive(state_dir):
                store = DeviceStore(
                    state_dir,
                    tenant="day18-a",
                    vehicle=vehicle,
                    ecu=ecu,
                    device="tbox-1",
                    ecu_type="body",
                    hardware_version="hw-1",
                )
                operation = store.prepare(job)
                store.close()
            claim = await api(
                "POST",
                path + "/claim",
                token=bearer(device="tbox-1"),
                body={"operation_id": operation},
            )
            await api(
                "POST",
                path + "/claim",
                token=bearer(device="other-device"),
                body={"operation_id": operation},
                expected=409,
            )
            async with admin.begin() as connection:
                await connection.execute(
                    text("UPDATE vehicles SET status='suspended' WHERE id=:v"), {"v": vehicle}
                )
            await api(
                "GET",
                path + "/artifact",
                token=bearer(device="tbox-1"),
                expected=409,
                extra_headers={"X-OTA-Claim": claim["claim_token"]},
            )
            await api(
                "POST",
                path + "/reports",
                token=bearer(device="tbox-1"),
                expected=409,
                body=dict(
                    event_id=str(uuid4()),
                    claim_token=claim["claim_token"],
                    sequence=1,
                    status="installing",
                    occurred_at=datetime.now(UTC).isoformat(),
                ),
            )
            async with admin.begin() as connection:
                await connection.execute(
                    text("UPDATE vehicles SET status='active' WHERE id=:v"), {"v": vehicle}
                )
            checks["inactive_vehicle_fences_download_and_transitions"] = True
            report = dict(
                event_id=str(uuid4()),
                claim_token=claim["claim_token"],
                sequence=2,
                status="succeeded",
                occurred_at=datetime.now(UTC).isoformat(),
                observed_sha256=hashlib.sha256(data).hexdigest(),
            )
            await api(
                "POST", path + "/reports", token=bearer(device="tbox-1"), body=report, expected=409
            )
            await api(
                "POST",
                path + "/reports",
                token=bearer(device="tbox-1"),
                body=report | {"claim_token": str(uuid4()), "sequence": 1, "status": "installing"},
                expected=409,
            )
            checks["ordered_reports_and_stale_claim_fenced"] = True
            cli = [
                sys.executable,
                "-m",
                "simulators.ota_device",
                "--base-url",
                f"http://127.0.0.1:{port}",
                "--tenant",
                "day18-a",
                "--vehicle",
                vehicle,
                "--ecu",
                ecu,
                "--device-id",
                "tbox-1",
                "--ecu-type",
                "body",
                "--hardware-version",
                "hw-1",
                "--state-dir",
                str(state_dir),
                "--token-file",
                str(device_token),
                "--trusted-keys",
                str(trust),
                "--ecu-private-key",
                str(ecu_key_path),
                "--bootstrap-image",
                str(factory),
                "--bootstrap-sha256",
                factory_digest,
                "--bootstrap-version",
                "1.0",
                "--bootstrap-security-version",
                "0",
            ]

            async def agent(
                target_job: str | None, *arguments: str, expected: int = 0
            ) -> dict[str, Any]:
                result = await asyncio.to_thread(
                    subprocess.run,
                    [*cli, *(["--job", target_job] if target_job else []), *arguments],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    timeout=45,
                )
                assert result.returncode == expected, result.stderr.decode(errors="replace")[-1000:]
                return json.loads(result.stdout) if expected == 0 else {}

            await agent(job, "--crash-at", "after_download", expected=86)
            checks["download_crash_recovered"] = True
            await agent(job, "--crash-at", "after_stage", expected=94)
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                assert db.execute("SELECT bank FROM active").fetchone()[0] == "A"
                assert (
                    db.execute("SELECT state FROM banks WHERE name='B'").fetchone()[0]
                    == "pending_boot"
                )
            await agent(job, "--crash-at", "after_boot", expected=95)
            await agent(job, "--crash-at", "after_install", expected=87)
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                assert db.execute("SELECT bank FROM active").fetchone()[0] == "B"
                assert (
                    db.execute("SELECT state FROM banks WHERE name='A'").fetchone()[0]
                    == "confirmed"
                )
                banks = dict(db.execute("SELECT name,sha256 FROM banks"))
                assert banks["A"] != banks["B"] == hashlib.sha256(data).hexdigest()
            checks["ab_bank_boot_confirmation_and_restart_recovery"] = True
            assert (await api("GET", f"/v2/ota/jobs/{job}"))["status"] == "installing"
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                assert db.execute("SELECT installations FROM active").fetchone()[0] == 1
                assert (
                    db.execute("SELECT count(*) FROM reports WHERE delivered=0").fetchone()[0] == 1
                )
            checks["activation_and_terminal_outbox_atomic"] = True
            device_token.write_text(bearer(device="tbox-1", expired=True))
            await agent(job, expected=1)
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                assert (
                    db.execute("SELECT count(*) FROM reports WHERE delivered=0").fetchone()[0] == 1
                )
            device_token.write_text(bearer(device="tbox-1"))
            checks["authentication_failure_retains_pending_report"] = True
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                first_report = json.loads(
                    db.execute("SELECT payload FROM reports WHERE sequence=1").fetchone()[0]
                )
                terminal_report = json.loads(
                    db.execute("SELECT payload FROM reports WHERE sequence=2").fetchone()[0]
                )
            for invalid_proof in (
                None,
                terminal_report["installation_proof"] | {"challenge": str(uuid4())},
                terminal_report["installation_proof"]
                | {"signature": base64.b64encode(bytes(64)).decode()},
            ):
                await api(
                    "POST",
                    path + "/reports",
                    token=bearer(device="tbox-1"),
                    body=terminal_report | {"installation_proof": invalid_proof},
                    expected=409,
                )
            checks["independent_signed_boot_proof_required"] = True
            await api(
                "POST",
                path + "/reports",
                token=bearer(device="tbox-1"),
                body=terminal_report
                | {
                    "occurred_at": (
                        datetime.fromisoformat(first_report["occurred_at"])
                        - timedelta(microseconds=1)
                    ).isoformat()
                },
                expected=409,
            )
            checks["regressed_report_time_denied"] = True
            async with admin.begin() as connection:
                await connection.execute(
                    text("""CREATE FUNCTION reject_day18_audit() RETURNS trigger
                    LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$""")
                )
                await connection.execute(
                    text("""CREATE TRIGGER reject_day18_audit BEFORE INSERT
                    ON ota_audit_events FOR EACH ROW EXECUTE FUNCTION reject_day18_audit()""")
                )
            try:
                await agent(job, expected=1)
                async with admin.connect() as connection:
                    assert (
                        await connection.scalar(
                            text("SELECT status FROM ota_jobs WHERE id=:id"), {"id": job}
                        )
                        == "installing"
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT security_version FROM ecu_inventory WHERE id=:id"),
                            {"id": ecu},
                        )
                        == 0
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT count(*) FROM ota_execution_reports WHERE job_id=:id"),
                            {"id": job},
                        )
                        == 1
                    )
                with sqlite3.connect(state_dir / "device.sqlite3") as db:
                    assert (
                        db.execute("SELECT count(*) FROM reports WHERE delivered=0").fetchone()[0]
                        == 1
                    )
            finally:
                async with admin.begin() as connection:
                    await connection.execute(
                        text("DROP TRIGGER reject_day18_audit ON ota_audit_events")
                    )
                    await connection.execute(text("DROP FUNCTION reject_day18_audit()"))
            checks["audit_failure_rolls_back_installation_report"] = True
            async with HTTPResponseDropProxy(port) as proxy:
                await agent(
                    job, "--base-url", proxy.url, "--crash-at", "after_terminal_ack", expected=88
                )
                assert proxy.dropped == 1 and proxy.confirmed_status == "HTTP/1.1 200 OK"
            checks["http_commit_response_lost_and_reconciled"] = True
            assert (await api("GET", f"/v2/ota/jobs/{job}"))["status"] == "succeeded"
            outcome = await agent(job)
            again = await agent(job)
            assert (
                outcome == again
                and outcome["active"]["installations"] == 1
                and outcome["pending_reports"] == 0
            )
            checks["lost_terminal_response_reconciled_idempotently"] = True
            checks["process_restart_single_activation"] = True
            image = state_dir / "images" / (hashlib.sha256(data).hexdigest() + ".bin")
            assert image.read_bytes() == data
            checks["pinned_historical_object_installed"] = True
            with sqlite3.connect(state_dir / "device.sqlite3") as db:
                terminal = json.loads(
                    db.execute("SELECT payload FROM reports WHERE sequence=2").fetchone()[0]
                )
            await api(
                "POST",
                path + "/reports",
                token=bearer(device="tbox-1"),
                body=terminal | {"observed_sha256": "0" * 64},
                expected=409,
            )
            checks["conflicting_terminal_event_rejected"] = True
            rollback, rollback_request = await candidate(version_name="0.9", security=1)
            await api(
                "POST", f"/v2/ota/jobs/{rollback}/verify", body=rollback_request, expected=409
            )
            await api(
                "POST",
                f"/ota/jobs/{rollback}/cancel",
                body={"reason": "anti rollback"},
                key=str(uuid4()),
            )
            checks["cloud_monotonic_security_version"] = True
            unhealthy, unhealthy_request = await candidate(version_name="3.0", security=2)
            await api("POST", f"/v2/ota/jobs/{unhealthy}/verify", body=unhealthy_request)
            failure = await agent(None, "--fail-health-check")
            assert failure["active"] == outcome["active"]
            assert (await api("GET", f"/v2/ota/jobs/{unhealthy}"))["status"] == "failed"
            checks["health_failure_preserves_previous_bank"] = True
            checks["device_discovers_verified_job"] = True
            current = await api("GET", f"/v2/vehicles/{vehicle}/ecus/{ecu}")
            assert current["security_version"] == 1 and current["firmware_version"] == "2.0"
            runtime_engine = create_database_engine(
                await load_runtime_database_settings(settings, "application")
            )
            try:
                for change in (
                    "security_version=0",
                    "firmware_version='forged'",
                    "security_version=999,firmware_version='forged-higher'",
                ):
                    with pytest.raises(DBAPIError) as rejected:
                        async with runtime_engine.begin() as connection:
                            await connection.execute(
                                text(f"UPDATE ecu_inventory SET {change} WHERE id=:id"), {"id": ecu}
                            )
                    assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
            finally:
                await runtime_engine.dispose()
            checks["database_monotonic_counter_guard"] = True
            runtime_engine = create_database_engine(
                await load_runtime_database_settings(settings, "application")
            )
            try:
                for sql in (
                    "UPDATE ota_jobs SET status='succeeded'",
                    "UPDATE ota_executions SET claim_token='forged'",
                    "UPDATE ota_executions SET report_sequence=2",
                    "INSERT INTO ota_execution_reports(tenant_id,id) VALUES('day18-a','forged')",
                    "INSERT INTO ota_executions(tenant_id,id) VALUES('day18-a','forged')",
                    "INSERT INTO ota_audit_events(tenant_id,id) VALUES('day18-a','forged')",
                    "SELECT * FROM ota_authority.receipt_keys",
                    "UPDATE ota_authority.receipt_keys SET enabled=true",
                    "INSERT INTO ecu_inventory(tenant_id,id,security_version) "
                    "VALUES ('day18-a','fake',999)",
                ):
                    with pytest.raises(DBAPIError) as rejected:
                        async with runtime_engine.begin() as connection:
                            await connection.execute(text(sql))
                    assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
                with pytest.raises(DBAPIError) as blocked:
                    async with runtime_engine.begin() as connection:
                        await connection.execute(
                            text(
                                "INSERT INTO ota_jobs(tenant_id,id,status) "
                                "VALUES('day18-a','forged','succeeded')"
                            )
                        )
                assert getattr(blocked.value.orig, "sqlstate", None) == "23514"
                with pytest.raises(DBAPIError):
                    async with runtime_engine.begin() as connection:
                        await connection.execute(
                            text("SELECT ota_transition(:p,:m)"),
                            dict(
                                p=json.dumps(
                                    dict(
                                        tenant_id="day18-a",
                                        protocol="cv-install/1",
                                        key_id="local-receipt-1",
                                        expires=int(time.time()) + 60,
                                    )
                                ),
                                m="0" * 64,
                            ),
                        )
                checks["all_sensitive_state_writes_are_controlled"] = True
                async with admin.connect() as connection:
                    authentic = await connection.scalar(
                        text(
                            "SELECT payload FROM ota_authority.installation_receipts "
                            "WHERE job_id=:job"
                        ),
                        {"job": job},
                    )
                secret = base64.b64decode(json.loads(receipt_keys.read_text())["day18-a"]["secret"])
                variants = [
                    authentic | {"ecu_id": other_ecu},
                    authentic | {"expires": 0},
                    authentic | {"expires": int(time.time()) + 9999},
                    authentic | {"expires": None},
                    authentic | {"manifest": authentic["manifest"] | {"security_version": 999}},
                ]
                for variant in variants:
                    receipt_payload = json.dumps(variant, sort_keys=True, separators=(",", ":"))
                    mac = hmac.new(secret, receipt_payload.encode(), hashlib.sha256).hexdigest()
                    with pytest.raises(DBAPIError):
                        async with runtime_engine.begin() as connection:
                            await connection.execute(
                                text("SELECT ota_apply_installation(:payload,:mac)"),
                                {"payload": receipt_payload, "mac": mac},
                            )
                receipt_payload = json.dumps(authentic)
                with pytest.raises(DBAPIError) as rejected:
                    async with runtime_engine.begin() as connection:
                        await connection.execute(
                            text("SELECT ota_apply_installation(:payload,:mac)"),
                            {"payload": receipt_payload, "mac": "0" * 64},
                        )
                assert getattr(rejected.value.orig, "sqlstate", None) == "42501"
                async with admin.connect() as connection:
                    assert (
                        await connection.scalar(
                            text(
                                "SELECT count(*) FROM ota_authority.installation_receipts "
                                "WHERE job_id=:job"
                            ),
                            {"job": job},
                        )
                        == 1
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT security_version FROM ecu_inventory WHERE id=:ecu"),
                            {"ecu": ecu},
                        )
                        == 1
                    )
            finally:
                await runtime_engine.dispose()
            checks["database_credential_cannot_forge_installation"] = True
            runtime_engine = create_database_engine(
                await load_runtime_database_settings(settings, "application")
            )
            try:
                for name in ("ota_apply_installation", "ota_transition"):
                    async with admin.connect() as connection:
                        definition = await connection.scalar(
                            text("SELECT pg_get_functiondef(CAST(:name AS regprocedure))"),
                            {"name": f"public.{name}(text,text)"},
                        )
                    async with admin.begin() as connection:
                        await connection.execute(
                            text(f"""CREATE OR REPLACE FUNCTION
                            public.{name}(p_payload text,p_mac text) RETURNS void
                            LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
                            AS $$ BEGIN RETURN; END $$""")
                        )
                    try:
                        with pytest.raises(RuntimeError, match="installation authority function"):
                            await verify_runtime_database_security(
                                runtime_engine, "application", tenant_id="day18-a"
                            )
                    finally:
                        async with admin.begin() as connection:
                            await connection.execute(text(definition))
                await verify_runtime_database_security(
                    runtime_engine, "application", tenant_id="day18-a"
                )
            finally:
                await runtime_engine.dispose()
            checks["database_authority_drift_fails_closed"] = True
            recovery_job, recovery_request = await candidate(version_name="4.0", security=3)
            await api("POST", f"/v2/ota/jobs/{recovery_job}/verify", body=recovery_request)
            recovery_path = f"/v2/vehicles/{vehicle}/ecus/{ecu}/ota-jobs/{recovery_job}"
            with exclusive(state_dir):
                local = DeviceStore(
                    state_dir,
                    tenant="day18-a",
                    vehicle=vehicle,
                    ecu=ecu,
                    device="tbox-1",
                    ecu_type="body",
                    hardware_version="hw-1",
                )
                recovery_operation = local.prepare(recovery_job)
                local.close()
            recovery_claim = ClaimResult.model_validate(
                await api(
                    "POST",
                    recovery_path + "/claim",
                    token=bearer(device="tbox-1"),
                    body={"operation_id": recovery_operation},
                )
            )
            with exclusive(state_dir):
                local = DeviceStore(
                    state_dir,
                    tenant="day18-a",
                    vehicle=vehicle,
                    ecu=ecu,
                    device="tbox-1",
                    ecu_type="body",
                    hardware_version="hw-1",
                )
                local.accept(recovery_claim)
                local.close()
            await operate(
                local_environment,
                "quarantine",
                "day18-a",
                str(uuid4()),
                "recovery-operator",
                "old agent stopped and isolated",
                {"job_id": recovery_job},
            )
            await api(
                "POST",
                recovery_path + "/claim",
                token=bearer(device="tbox-1"),
                body={"operation_id": recovery_operation},
                expected=409,
            )
            observed = probe(state_dir, recovery_claim, ecu_key_path, trust, observed=True)
            recovery_settings = local_environment.model_copy(
                update={"ota_device_keys_file": str(ecu_registry)}
            )
            reconcile_operation = str(uuid4())
            reconciliation = {"job_id": recovery_job, "proof": observed.model_dump(mode="json")}
            await operate(
                recovery_settings,
                "reconcile",
                "day18-a",
                reconcile_operation,
                "recovery-operator",
                "observed confirmed old bank",
                reconciliation,
            )
            await operate(
                recovery_settings,
                "reconcile",
                "day18-a",
                reconcile_operation,
                "recovery-operator",
                "observed confirmed old bank",
                reconciliation,
            )
            await agent(recovery_job, "--reconcile")
            await api(
                "GET",
                recovery_path + "/artifact",
                token=bearer(device="tbox-1"),
                extra_headers={"X-OTA-Claim": str(recovery_claim.claim_token)},
                expected=409,
            )
            assert (await api("GET", f"/v2/ota/jobs/{recovery_job}"))["status"] == "failed"
            checks["claim_quarantine_reconciliation_fences_old_owner"] = True
            rotated = ed25519.Ed25519PrivateKey.generate()
            rotation = registry(
                "day18-a",
                "manufacturer-2",
                rotated.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            )
            await operate(
                local_environment,
                "publisher-register",
                "day18-a",
                str(uuid4()),
                "key-operator",
                "planned overlapping rotation",
                {"keys": rotation["tenants"]["day18-a"]},
            )
            current_keys = json.loads(trust.read_text())
            current_keys["tenants"]["day18-a"].update(rotation["tenants"]["day18-a"])
            trust.write_text(json.dumps(current_keys))
            rotated_job, rotated_request = await candidate(
                version_name="5.0", security=4, publisher="manufacturer-2", signing=rotated
            )
            await api("POST", f"/v2/ota/jobs/{rotated_job}/verify", body=rotated_request)
            await operate(
                local_environment,
                "publisher-revoke",
                "day18-a",
                str(uuid4()),
                "key-operator",
                "revocation drill",
                {"key_id": "manufacturer-2"},
            )
            await api(
                "POST",
                f"/v2/vehicles/{vehicle}/ecus/{ecu}/ota-jobs/{rotated_job}/claim",
                token=bearer(device="tbox-1"),
                body={"operation_id": str(uuid4())},
                expected=409,
            )
            await operate(
                local_environment,
                "quarantine",
                "day18-a",
                str(uuid4()),
                "key-operator",
                "withdraw unclaimed revoked publication",
                {"job_id": rotated_job},
            )
            checks["publisher_rotation_revocation_and_audit"] = True
            adopted_ecu = str(uuid4())
            adopted_state = tmp_path / "adopted-device"
            adopted_key = ed25519.Ed25519PrivateKey.generate()
            adopted_key_file = tmp_path / "adopted-ecu.pem"
            adopted_key_file.write_bytes(
                adopted_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            adopted_token = tmp_path / "adopted-token"
            adopted_token.write_text(bearer(device="tbox-2"))
            device_keys = json.loads(ecu_registry.read_text())
            device_keys["day18-a"]["tbox-2"] = {
                adopted_ecu: dict(
                    vehicle_id=vehicle,
                    install_allowed=True,
                    public_key=base64.b64encode(
                        adopted_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                    ).decode(),
                )
            }
            ecu_registry.write_text(json.dumps(device_keys))
            await api(
                "PUT",
                f"/vehicles/{vehicle}/ecus/{adopted_ecu}",
                body=dict(
                    ecu_type="body",
                    hardware_version="hw-1",
                    firmware_version="1.0",
                    serial_number="body-adopt",
                ),
            )
            await operate(
                local_environment,
                "bootstrap",
                "day18-a",
                str(uuid4()),
                "factory-operator",
                "controlled second ECU bootstrap",
                dict(
                    vehicle_id=vehicle,
                    ecu_id=adopted_ecu,
                    firmware_version="1.0",
                    security_version=0,
                    sha256=factory_digest,
                ),
            )
            adopted_job, adopted_request = await candidate(
                target=adopted_ecu, version_name="6.0", security=1
            )
            await api("POST", f"/v2/ota/jobs/{adopted_job}/verify", body=adopted_request)
            adopted_args = [
                "--ecu",
                adopted_ecu,
                "--device-id",
                "tbox-2",
                "--state-dir",
                str(adopted_state),
                "--token-file",
                str(adopted_token),
                "--ecu-private-key",
                str(adopted_key_file),
            ]
            await agent(adopted_job, *adopted_args, "--crash-at", "after_install", expected=87)
            with sqlite3.connect(adopted_state / "device.sqlite3") as db:
                captured = json.loads(
                    db.execute("SELECT claim FROM jobs WHERE id=?", (adopted_job,)).fetchone()[0]
                )
            adopted_claim = ClaimResult(
                job=ExecutionView.model_validate(await api("GET", f"/v2/ota/jobs/{adopted_job}")),
                device_id="tbox-2",
                **captured,
            )
            await operate(
                local_environment,
                "quarantine",
                "day18-a",
                str(uuid4()),
                "recovery-operator",
                "crashed device fenced before candidate adoption",
                {"job_id": adopted_job},
            )
            adopted_observation = probe(
                adopted_state, adopted_claim, adopted_key_file, trust, observed=True
            )
            adoption = {"job_id": adopted_job, "proof": adopted_observation.model_dump(mode="json")}
            adoption_operation = str(uuid4())
            adoption_settings = recovery_settings.model_copy(
                update={"ota_trusted_keys_file": str(trust)}
            )
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "CREATE FUNCTION ota_authority.fail_resolution_audit() RETURNS trigger "
                        "LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='reconcile' THEN "
                        "RAISE EXCEPTION 'injected reconciliation audit failure'; "
                        "END IF; RETURN NEW; END $$"
                    )
                )
                await connection.execute(
                    text(
                        "CREATE TRIGGER fail_resolution_audit BEFORE INSERT ON "
                        "ota_authority.management_audit FOR EACH ROW EXECUTE FUNCTION "
                        "ota_authority.fail_resolution_audit()"
                    )
                )
            try:
                with pytest.raises(DBAPIError):
                    await operate(
                        adoption_settings,
                        "reconcile",
                        "day18-a",
                        adoption_operation,
                        "recovery-operator",
                        "verified candidate boot",
                        adoption,
                    )
                async with admin.connect() as connection:
                    assert (
                        await connection.scalar(
                            text("SELECT security_version FROM ecu_inventory WHERE id=:e"),
                            {"e": adopted_ecu},
                        )
                        == 0
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT status FROM ota_jobs WHERE id=:j"), {"j": adopted_job}
                        )
                        == "installing"
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT report_sequence FROM ota_executions WHERE id=:j"),
                            {"j": adopted_job},
                        )
                        == 1
                    )
                    assert (
                        await connection.scalar(
                            text(
                                "SELECT count(*) FROM ota_authority.installation_receipts "
                                "WHERE job_id=:j"
                            ),
                            {"j": adopted_job},
                        )
                        == 0
                    )
            finally:
                async with admin.begin() as connection:
                    await connection.execute(
                        text("DROP TRIGGER fail_resolution_audit ON ota_authority.management_audit")
                    )
                    await connection.execute(
                        text("DROP FUNCTION ota_authority.fail_resolution_audit()")
                    )
            await operate(
                adoption_settings,
                "reconcile",
                "day18-a",
                adoption_operation,
                "recovery-operator",
                "verified candidate boot",
                adoption,
            )
            await operate(
                adoption_settings,
                "reconcile",
                "day18-a",
                adoption_operation,
                "recovery-operator",
                "verified candidate boot",
                adoption,
            )
            await agent(adopted_job, *adopted_args, "--reconcile")
            assert (await api("GET", f"/v2/vehicles/{vehicle}/ecus/{adopted_ecu}"))[
                "security_version"
            ] == 1
            async with admin.connect() as connection:
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ota_execution_reports WHERE job_id=:j"),
                        {"j": adopted_job},
                    )
                    == 2
                )
                assert (
                    await connection.scalar(
                        text(
                            "SELECT count(*) FROM ota_audit_events "
                            "WHERE resource_id=:j AND action='reconcile'"
                        ),
                        {"j": adopted_job},
                    )
                    == 1
                )
            checks["candidate_boot_reconciliation_is_atomic"] = True
            image.write_bytes(b"damaged local bank")
            await agent(job, expected=1)
            image.write_bytes(data)
            checks["active_image_corruption_fails_closed"] = True
            async with admin.connect() as connection:
                installed = (
                    (
                        await connection.execute(
                            text(
                                "SELECT firmware_version,security_version FROM ecu_inventory "
                                "WHERE id=:id"
                            ),
                            {"id": ecu},
                        )
                    )
                    .mappings()
                    .one()
                )
                assert dict(installed) == dict(firmware_version="2.0", security_version=1)
                records = (
                    await connection.execute(
                        text(
                            "SELECT action,count(*) FROM ota_audit_events "
                            "WHERE resource_id=:id GROUP BY action"
                        ),
                        {"id": job},
                    )
                ).all()
                counts: dict[str, int] = dict(records)
                assert counts["verify"] == 1 and counts["claim"] == 1 and counts["report"] == 2
                assert (
                    await connection.scalar(
                        text("SELECT count(*) FROM ota_execution_reports WHERE job_id=:id"),
                        {"id": job},
                    )
                    == 2
                )
            checks["cloud_inventory_reports_and_audit_agree"] = True
            write_json(
                Path(os.environ["RUNTIME_EVIDENCE_DIR"]) / "day18-ota-execution.json",
                dict(
                    version=1,
                    day18_sha256=source_digest(),
                    profile="local_drill",
                    provenance=provenance(),
                    checks=checks,
                    generated_at_utc=datetime.now(UTC).isoformat(),
                    simulated_installation=True,
                    physical_boot_verified=False,
                    real_aws_verified=False,
                    device_installations=1,
                    cloud_security_version=1,
                    device_security_version=outcome["active"]["security_version"],
                    pending_reports=0,
                ),
            )
    finally:
        if process is not None and process.poll() is None:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
            try:
                await asyncio.to_thread(process.wait, 5)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 5)
        log.close()
        await admin.dispose()
