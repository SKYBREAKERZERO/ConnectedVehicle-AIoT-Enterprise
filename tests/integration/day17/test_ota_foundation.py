from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2 as httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from apps.api.main import create_app
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import (
    OTA_TABLES,
    verify_runtime_database_security,
)
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.security.context import SecurityContext, bind_security_context
from enterprise_platform.security.identity import Principal, PrincipalType, Role
from scripts.day16_evidence import provenance
from scripts.day17_release import write_json
from tests.integration.day12.test_credential_cloud_contracts import prepare
from tests.unit.test_ota_contracts import firmware


async def state(engine: AsyncEngine) -> dict[str, list[str]]:
    async with engine.connect() as connection:
        return {
            table: list(
                (
                    await connection.scalars(
                        text(
                            f"SELECT to_jsonb(t)::text FROM public.{table} t "
                            "ORDER BY to_jsonb(t)::text"
                        )
                    )
                ).all()
            )
            for table in OTA_TABLES
        }


@pytest.mark.integration
async def test_real_ota_api_database_isolation_idempotency_audit_and_concurrency(
    local_environment: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    admin = create_database_engine(local_environment)
    engines = []
    checks: dict[str, bool] = {}
    vehicles = [str(uuid4()), str(uuid4())]
    ecu, ecu2, foreign_ecu = (str(uuid4()) for _ in range(3))
    configuration = []
    try:
        for index, owner in enumerate(("ota-a", "ota-b")):
            _, _, settings, _ = await prepare(local_environment, owner)
            configuration.append(settings)
            configured_runtime = await load_runtime_database_settings(settings, "application")
            engine = create_database_engine(configured_runtime)
            engines.append(engine)
            await verify_runtime_database_security(engine, "application", tenant_id=owner)
            async with admin.begin() as connection:
                await connection.execute(
                    text(
                        "INSERT INTO vehicles (id,vin,tenant_id,status,created_at,updated_at) "
                        "VALUES (:id,:vin,:tenant,'active',now(),now())"
                    ),
                    {"id": vehicles[index], "vin": uuid4().hex[:17].upper(), "tenant": owner},
                )
        apps = [create_app(), create_app()]
        for app, engine in zip(apps, engines, strict=True):
            app.state.session_factory = create_session_factory(engine)
        contexts = [
            SecurityContext(
                Principal(
                    "ota-operator-" + owner,
                    PrincipalType.USER,
                    tenant_id=owner,
                    roles=frozenset({Role.OTA_OPERATOR}),
                )
            )
            for owner in ("ota-a", "ota-b")
        ]
        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=apps[0], raise_app_exceptions=False),
                base_url="http://local",
                trust_env=False,
            ) as client,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=apps[1], raise_app_exceptions=False),
                base_url="http://local",
                trust_env=False,
            ) as foreign,
        ):

            async def request(
                method: str, path: str, *, tenant_index: int = 0, expected: int, **kwargs: Any
            ) -> dict[str, Any] | list[Any]:
                with bind_security_context(contexts[tenant_index]):
                    response = await (client if tenant_index == 0 else foreign).request(
                        method, path, **kwargs
                    )
                assert response.status_code == expected, response.text
                return response.json()  # type: ignore[no-any-return]

            registration = dict(
                ecu_type="body",
                hardware_version="hw-1",
                firmware_version="1.0.0",
                serial_number="body-a",
            )
            inventory = f"/vehicles/{vehicles[0]}/ecus/{ecu}"
            first = await request("PUT", inventory, json=registration, expected=200)
            repeat = await request("PUT", inventory, json=registration, expected=200)
            assert isinstance(first, dict) and isinstance(repeat, dict)
            assert first["created"] and not repeat["created"]
            await request(
                "PUT",
                f"/vehicles/{vehicles[0]}/ecus/{ecu2}",
                json=registration | {"serial_number": "body-a2"},
                expected=200,
            )
            await request(
                "PUT",
                f"/vehicles/{vehicles[1]}/ecus/{foreign_ecu}",
                tenant_index=1,
                json=registration | {"serial_number": "body-b"},
                expected=200,
            )
            checks["inventory_registration_idempotent"] = True
            body = firmware()
            created = await request(
                "POST",
                "/ota/firmware-releases",
                json=body,
                headers={"Idempotency-Key": "release-a"},
                expected=201,
            )
            assert isinstance(created, dict)
            release = created["release"]["id"]
            assert created["release"]["verification_status"] == "unverified"
            repeated = await request(
                "POST",
                "/ota/firmware-releases",
                json=body,
                headers={"Idempotency-Key": "release-a"},
                expected=201,
            )
            assert isinstance(repeated, dict) and not repeated["created"]
            alien = await request(
                "POST",
                "/ota/firmware-releases",
                tenant_index=1,
                json=body,
                headers={"Idempotency-Key": "release-b"},
                expected=201,
            )
            assert isinstance(alien, dict)
            alien_release = alien["release"]["id"]
            before = await state(admin)
            await request(
                "PUT", inventory, json=registration | {"hardware_version": "hw-2"}, expected=409
            )
            await request(
                "POST",
                "/ota/firmware-releases",
                json=body | {"sha256": "b" * 64},
                headers={"Idempotency-Key": "release-a"},
                expected=409,
            )
            await request("POST", "/ota/firmware-releases", json=body, expected=422)
            await request(
                "POST",
                "/ota/firmware-releases",
                json=body,
                headers={"Idempotency-Key": " "},
                expected=400,
            )
            await request(
                "POST",
                "/ota/firmware-releases",
                json=body | {"tenant_id": "ota-b"},
                headers={"Idempotency-Key": "forged"},
                expected=422,
            )
            await request("GET", f"/ota/firmware-releases/{alien_release}", expected=404)
            await request("GET", f"/vehicles/{vehicles[1]}/ecus", expected=404)
            await request(
                "POST",
                inventory + "/ota-jobs",
                json={"release_id": alien_release},
                headers={"Idempotency-Key": "alien"},
                expected=404,
            )
            assert await state(admin) == before
            checks["negative_requests_no_side_effects"] = True
            checks["release_immutable_and_idempotent"] = True
            checks["cross_tenant_api_denied"] = True
            with bind_security_context(
                SecurityContext(
                    Principal(
                        "owner",
                        PrincipalType.USER,
                        tenant_id="ota-a",
                        roles=frozenset({Role.VEHICLE_OWNER}),
                    )
                )
            ):
                assert (await client.get("/ota/firmware-releases")).status_code == 403
            assert (await client.get("/ota/firmware-releases")).status_code == 401
            checks["authentication_and_ota_permission_required"] = True

            wrong = await request(
                "POST",
                "/ota/firmware-releases",
                json=body | {"hardware_version": "other"},
                headers={"Idempotency-Key": "wrong-hw"},
                expected=201,
            )
            assert isinstance(wrong, dict)
            before = await state(admin)
            await request(
                "POST",
                inventory + "/ota-jobs",
                json={"release_id": wrong["release"]["id"]},
                headers={"Idempotency-Key": "bad-job"},
                expected=409,
            )
            assert await state(admin) == before
            checks["hardware_mismatch_rejected"] = True

            async def create() -> dict[str, Any] | list[Any]:
                return await request(
                    "POST",
                    inventory + "/ota-jobs",
                    json={"release_id": release},
                    headers={"Idempotency-Key": "concurrent-job"},
                    expected=202,
                )

            results = await asyncio.gather(create(), create())
            assert all(isinstance(row, dict) for row in results)
            rows = [row for row in results if isinstance(row, dict)]
            assert sorted(row["created"] for row in rows) == [False, True]
            assert rows[0]["job"]["id"] == rows[1]["job"]["id"]
            job = rows[0]["job"]["id"]
            assert rows[0]["job"]["status"] == "pending_verification"
            checks["concurrent_duplicate_single_job"] = True
            before = await state(admin)
            await request(
                "POST",
                inventory + "/ota-jobs",
                json={"release_id": release},
                headers={"Idempotency-Key": "other-active"},
                expected=409,
            )
            await request(
                "POST",
                inventory + "/ota-jobs",
                json={"release_id": wrong["release"]["id"]},
                headers={"Idempotency-Key": "concurrent-job"},
                expected=409,
            )
            await request("GET", f"/ota/jobs/{job}", tenant_index=1, expected=404)
            assert await state(admin) == before
            checks["one_outstanding_job_per_ecu"] = True
            checks["job_idempotency_conflicts_rejected"] = True
            listed = await request("GET", inventory + "/ota-jobs", expected=200)
            assert isinstance(listed, list) and len(listed) == 1
            checks["job_query_persisted"] = True

            # Fail the actual audit INSERT, after the service has modified the job.
            async with admin.begin() as connection:
                await connection.execute(
                    text("""CREATE FUNCTION public.reject_ota_audit() RETURNS trigger
                    LANGUAGE plpgsql AS $$ BEGIN
                    RAISE EXCEPTION 'injected audit failure'; END $$""")
                )
                await connection.execute(
                    text("""CREATE TRIGGER reject_ota_audit BEFORE INSERT
                    ON public.ota_audit_events FOR EACH ROW
                    EXECUTE FUNCTION public.reject_ota_audit()""")
                )
            before = await state(admin)
            try:
                await request(
                    "POST",
                    f"/ota/jobs/{job}/cancel",
                    json={"reason": "maintenance"},
                    headers={"Idempotency-Key": "cancel-a"},
                    expected=500,
                )
                await request(
                    "POST",
                    f"/vehicles/{vehicles[0]}/ecus/{ecu2}/ota-jobs",
                    json={"release_id": release},
                    headers={"Idempotency-Key": "audit-failure"},
                    expected=500,
                )
                assert await state(admin) == before
            finally:
                async with admin.begin() as connection:
                    await connection.execute(
                        text("DROP TRIGGER reject_ota_audit ON public.ota_audit_events")
                    )
                    await connection.execute(text("DROP FUNCTION public.reject_ota_audit()"))
            checks["audit_failure_rolls_back_create_and_cancel"] = True
            cancelled = await request(
                "POST",
                f"/ota/jobs/{job}/cancel",
                json={"reason": "maintenance"},
                headers={"Idempotency-Key": "cancel-a"},
                expected=200,
            )
            before = await state(admin)
            again = await request(
                "POST",
                f"/ota/jobs/{job}/cancel",
                json={"reason": "maintenance"},
                headers={"Idempotency-Key": "cancel-a"},
                expected=200,
            )
            assert again == cancelled and await state(admin) == before
            await request(
                "POST",
                f"/ota/jobs/{job}/cancel",
                json={"reason": "different"},
                headers={"Idempotency-Key": "cancel-a"},
                expected=409,
            )
            assert await state(admin) == before
            checks["cancellation_idempotent_and_audited"] = True

            # Distinct operation IDs racing for one ECU still permit only one pending intent.
            async def competing(key: str) -> httpx.Response:
                with bind_security_context(contexts[0]):
                    return await client.post(
                        f"/vehicles/{vehicles[0]}/ecus/{ecu2}/ota-jobs",
                        json={"release_id": release},
                        headers={"Idempotency-Key": key},
                    )

            competing_results = await asyncio.gather(competing("race-a"), competing("race-b"))
            assert sorted(row.status_code for row in competing_results) == [202, 409]
            checks["competing_operations_single_active_job"] = True

        async with engines[0].begin() as connection:
            await connection.execute(text("SELECT set_config('app.tenant_id','ota-b',true)"))
            for table in OTA_TABLES:
                assert (
                    await connection.scalar(
                        text(f"SELECT count(*) FROM {table} WHERE tenant_id='ota-b'")
                    )
                    == 0
                )
        checks["fixed_login_rls_blocks_forged_context"] = True
        for runtime in DATABASE_USERS:
            if runtime == "application":
                continue
            engine = create_database_engine(
                await load_runtime_database_settings(configuration[0], runtime)
            )
            try:
                for table in OTA_TABLES:
                    with pytest.raises(DBAPIError):
                        async with engine.begin() as connection:
                            await connection.execute(text(f"SELECT * FROM {table}"))
            finally:
                await engine.dispose()
        checks["workers_denied_all_ota_tables"] = True
        for sql in (
            "UPDATE firmware_releases SET sha256=sha256",
            "DELETE FROM ota_audit_events",
            "UPDATE ota_jobs SET release_id=release_id",
            "CREATE TABLE ota_bad(id int)",
        ):
            with pytest.raises(DBAPIError):
                async with engines[0].begin() as connection:
                    await connection.execute(text(sql))
        checks["runtime_ddl_and_immutable_updates_denied"] = True
        before = await state(admin)
        # Raw SQL bypasses the API compatibility check: composite FKs must still reject it.
        for tenant_id, vehicle_id, release_id in (
            ("ota-a", vehicles[1], release),
            ("ota-a", vehicles[0], alien_release),
            ("ota-a", vehicles[0], wrong["release"]["id"]),
        ):
            with pytest.raises(DBAPIError):
                async with engines[0].begin() as connection:
                    await connection.execute(
                        text("""INSERT INTO ota_jobs
                        (tenant_id,id,vehicle_id,ecu_id,release_id,ecu_type,hardware_version,
                         status,idempotency_key,created_at,updated_at,created_by)
                        VALUES (:tenant,:id,:vehicle,:ecu,:release,'body','hw-1',
                                'pending_verification',:key,now(),now(),'sql-probe')"""),
                        {
                            "tenant": tenant_id,
                            "id": str(uuid4()),
                            "vehicle": vehicle_id,
                            "ecu": ecu,
                            "release": release_id,
                            "key": str(uuid4()),
                        },
                    )
        assert await state(admin) == before
        checks["composite_foreign_keys_enforce_ownership_and_hardware"] = True
        async with admin.begin() as connection:
            await connection.execute(
                text("ALTER TABLE firmware_releases NO FORCE ROW LEVEL SECURITY")
            )
        try:
            with pytest.raises(RuntimeError, match="Unsafe runtime database schema"):
                await verify_runtime_database_security(engines[0], "application", tenant_id="ota-a")
        finally:
            async with admin.begin() as connection:
                await connection.execute(
                    text("ALTER TABLE firmware_releases FORCE ROW LEVEL SECURITY")
                )
        checks["rls_force_drift_rejected"] = True
        async with admin.connect() as connection:
            audit = (
                (await connection.execute(text("SELECT * FROM ota_audit_events"))).mappings().all()
            )
            assert (
                len(
                    [
                        row
                        for row in audit
                        if row["resource_id"] == job and row["action"] == "create"
                    ]
                )
                == 1
            )
            assert (
                len(
                    [
                        row
                        for row in audit
                        if row["resource_id"] == job and row["action"] == "cancel"
                    ]
                )
                == 1
            )
            assert all(
                row["actor_id"].startswith("ota-operator-") and row["occurred_at"] for row in audit
            )
        checks["audit_actor_time_and_single_operation"] = True
        checks["runtime_security_contract_verified"] = True
        write_json(
            Path(os.environ["RUNTIME_EVIDENCE_DIR"]) / "day17-ota-foundation.json",
            dict(
                version=1,
                profile="local_drill",
                provenance=provenance(),
                checks=checks,
                generated_at_utc=datetime.now(UTC).isoformat(),
                real_aws_verified=False,
                device_execution_verified=False,
            ),
        )
    finally:
        for engine in engines:
            await engine.dispose()
        await admin.dispose()
