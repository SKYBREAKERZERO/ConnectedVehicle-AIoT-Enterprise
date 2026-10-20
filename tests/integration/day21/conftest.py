"""Disposable PostgreSQL 16 only: missing Docker is a hard test failure."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncEngine

from connected_vehicle.ota.artifacts import ArtifactVerifier
from connected_vehicle.ota.campaign_contracts import CampaignView
from connected_vehicle.ota.campaign_service import CampaignService
from connected_vehicle.ota.models import ECUModel, FirmwareModel
from connected_vehicle.ota.service import OTAService
from connected_vehicle.vehicle.persistence.models import VehicleModel
from database.bootstrap_cluster import bootstrap
from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, runtime_database_user
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.session import create_session_factory

ROOT = Path(__file__).resolve().parents[3]


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60, check=True
    )
    return result.stdout.strip()


@pytest.fixture(scope="module")
def postgres() -> Iterator[Settings]:
    name = "cv-day21-" + uuid4().hex[:12]
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_PASSWORD=day21-bootstrap",
        "postgres:16-alpine",
    )
    try:
        port = int(docker("port", name, "5432").rsplit(":", 1)[1])
        deadline = time.monotonic() + 45
        while subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True
        ).returncode:
            if time.monotonic() > deadline:
                raise TimeoutError("Day21 PostgreSQL did not start")
            time.sleep(0.2)
        settings = Settings.model_construct(
            database_host="127.0.0.1",
            database_port=port,
            database_name="postgres",
            database_username="postgres",
            database_password=SecretStr("day21-bootstrap"),
            bootstrap_database_username="postgres",
            bootstrap_database_password=SecretStr("day21-bootstrap"),
            migration_database_username="migration_owner",
            migration_database_password=SecretStr("day21-migration"),
        )
        asyncio.run(bootstrap(settings))
        environment = dict(
            os.environ,
            DATABASE_HOST="127.0.0.1",
            DATABASE_PORT=str(port),
            DATABASE_NAME="postgres",
            MIGRATION_DATABASE_USERNAME="migration_owner",
            MIGRATION_DATABASE_PASSWORD="day21-migration",
        )
        environment.pop("DATABASE_TENANT_ID", None)
        migrated = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert migrated.returncode == 0, migrated.stdout + migrated.stderr
        yield settings
    finally:
        docker("rm", "-f", name)


@dataclass
class World:
    tenant: str
    admin: AsyncEngine
    runtime: AsyncEngine
    service: CampaignService
    release: str
    ecus: list[str]
    settings: Settings

    async def campaign(self, ecus: list[str] | None = None) -> str:
        identifier = str(uuid4())
        manifest = dict(
            protocol="cv-ota/2",
            tenant_id=self.tenant,
            release_id=self.release,
            ecu_type="body",
            hardware_version="hw1",
            version="2.0",
            artifact_bucket="day21-fixture",
            artifact_key="body/2.0/firmware.bin",
            artifact_version="pinned-version",
            sha256="a" * 64,
            size_bytes=16,
            security_version=1,
            key_id="publisher",
        )
        commands: list[tuple[str, dict[str, Any]]] = [
            (
                "create",
                dict(
                    name="Day21",
                    manifest=manifest,
                    signature="A" * 88,
                    canary_size=1,
                    wave_size=1,
                    max_failures=0,
                    observation_seconds=0,
                    wave_timeout_seconds=60,
                ),
            ),
            ("freeze", {"ecu_ids": ecus or self.ecus}),
            ("start", {}),
        ]
        for action, body in commands:
            await self.service.command(
                self.tenant, "day21-test", identifier, action, str(uuid4()), body, "Day21 drill"
            )
        return identifier

    async def tick(self, campaign: str, operation: str | None = None) -> CampaignView:
        return await self.service.command(
            self.tenant,
            "day21-test",
            campaign,
            "tick",
            operation or str(uuid4()),
            {"publisher_valid": True},
            "Day21 drill",
        )

    async def count(self, table: str) -> int:
        assert table in {"ota_jobs", "ota_campaign_events", "ota_audit_events"}
        async with self.admin.connect() as connection:
            return int(
                await connection.scalar(
                    text(f"SELECT count(*) FROM public.{table} WHERE tenant_id=:t"),
                    {"t": self.tenant},
                )
                or 0
            )


@pytest.fixture
async def world(postgres: Settings, tmp_path: Path) -> AsyncIterator[World]:
    tenant = "day21-" + uuid4().hex
    roles = {runtime: runtime_database_user(runtime, tenant) for runtime in DATABASE_USERS}
    await prepare_roles(postgres, roles)
    await grant_runtimes(postgres, roles, tenant)
    admin = create_database_engine(postgres)
    key = secrets.token_bytes(32)
    authority = tmp_path / "authority.json"
    authority.write_text(
        json.dumps(
            {
                tenant: {
                    "key_id": "day21-authority",
                    "secret": base64.b64encode(key).decode(),
                }
            }
        ),
        encoding="utf-8",
    )
    settings = postgres.model_copy(
        update={
            "database_username": roles["application"],
            "database_password": SecretStr("day21-runtime"),
            "database_tenant_id": tenant,
            "ota_install_receipt_keys_file": str(authority),
        }
    )
    runtime = create_database_engine(settings)
    service = CampaignService(
        OTAService(create_session_factory(runtime)), ArtifactVerifier(settings)
    )
    release = str(uuid4())
    ecus = [str(uuid4()) for _ in range(4)]
    now = datetime.now(UTC)
    try:
        async with admin.begin() as connection:
            await connection.execute(
                text(f"ALTER ROLE {roles['application']} PASSWORD 'day21-runtime'")
            )
            await connection.execute(
                text(
                    "INSERT INTO ota_authority.receipt_keys(tenant_id,key_id,secret) "
                    "VALUES(:t,'day21-authority',:k)"
                ),
                dict(t=tenant, k=key),
            )
            await connection.execute(
                text(
                    "INSERT INTO ota_authority.publisher_keys "
                    "VALUES(:t,'publisher','test-public-key',now()-interval '1 day',"
                    "now()+interval '1 day',false)"
                ),
                dict(t=tenant),
            )
            await connection.execute(
                insert(FirmwareModel),
                dict(
                    tenant_id=tenant,
                    id=release,
                    ecu_type="body",
                    hardware_version="hw1",
                    version="2.0",
                    artifact_bucket="day21-fixture",
                    artifact_key="body/2.0/firmware.bin",
                    artifact_version="pinned-version",
                    sha256="a" * 64,
                    size_bytes=16,
                    idempotency_key="fixture",
                    created_at=now,
                    created_by="fixture",
                ),
            )
            for ecu in ecus:
                vehicle = str(uuid4())
                await connection.execute(
                    insert(VehicleModel),
                    dict(
                        id=vehicle,
                        tenant_id=tenant,
                        vin=uuid4().hex[:17].upper(),
                        status="active",
                        created_at=now,
                        updated_at=now,
                    ),
                )
                await connection.execute(
                    insert(ECUModel),
                    dict(
                        tenant_id=tenant,
                        id=ecu,
                        vehicle_id=vehicle,
                        ecu_type="body",
                        hardware_version="hw1",
                        firmware_version="1.0",
                        security_version=0,
                        bootstrap_confirmed=True,
                        serial_number=ecu,
                        created_at=now,
                        created_by="fixture",
                    ),
                )
                await connection.execute(
                    text(
                        "INSERT INTO ota_authority.ecu_bootstrap VALUES "
                        "(:t,:e,:v,'1.0',0,:sha,'fixture','drill',CAST(:op AS uuid))"
                    ),
                    dict(t=tenant, e=ecu, v=vehicle, sha="b" * 64, op=str(uuid4())),
                )
        yield World(tenant, admin, runtime, service, release, ecus, settings)
    finally:
        await runtime.dispose()
        await admin.dispose()
