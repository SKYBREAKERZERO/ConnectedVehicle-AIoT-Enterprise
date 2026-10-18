from __future__ import annotations

import asyncio
import subprocess
import sys

import pytest
from sqlalchemy import text

from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    migration_database_settings,
    runtime_database_user,
)
from enterprise_platform.database.engine import create_database_engine
from tests.integration.day12.conftest import migration_environment


@pytest.mark.integration
async def test_forward_migration_revokes_existing_base_and_tenant_grants(
    local_environment: Settings,
) -> None:
    environment = migration_environment(local_environment)
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-m", "alembic", "upgrade", "d72fa60b319e"],
        env=environment,
        capture_output=True,
    )
    assert result.returncode == 0
    roles = {runtime: runtime_database_user(runtime, "upgrade-probe") for runtime in DATABASE_USERS}
    await prepare_roles(local_environment, roles)
    await grant_runtimes(local_environment, roles, "upgrade-probe")
    owner = create_database_engine(migration_database_settings(local_environment))
    try:
        async with owner.begin() as connection:
            # Reproduce the published predecessor's direct version-write capability.
            await connection.execute(
                text(
                    "GRANT UPDATE(firmware_version,security_version) ON ecu_inventory "
                    f'TO "{roles["application"]}"'
                )
            )
            for role in ("app_user", roles["application"]):
                assert await connection.scalar(
                    text(
                        "SELECT has_column_privilege(:role,'ecu_inventory',"
                        "'security_version','UPDATE')"
                    ),
                    {"role": role},
                )
        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=environment,
            capture_output=True,
        )
        assert result.returncode == 0
        async with owner.connect() as connection:
            for role in ("app_user", roles["application"]):
                for permission in ("UPDATE", "INSERT"):
                    assert not await connection.scalar(
                        text(
                            "SELECT has_column_privilege(:role,'ecu_inventory',"
                            "'security_version',:permission)"
                        ),
                        {"role": role, "permission": permission},
                    )
    finally:
        await owner.dispose()


@pytest.mark.integration
async def test_unknown_local_revision_is_refused_without_stamping(
    local_environment: Settings,
) -> None:
    environment = migration_environment(local_environment)
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=environment,
        capture_output=True,
    )
    assert result.returncode == 0
    engine = create_database_engine(local_environment)
    try:
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE alembic_version SET version_num='d72a91b63ef0'"))
        result = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=environment,
            capture_output=True,
        )
        assert result.returncode != 0 and b"d72a91b63ef0" in result.stderr + result.stdout
        async with engine.connect() as connection:
            assert (
                await connection.scalar(text("SELECT version_num FROM alembic_version"))
                == "d72a91b63ef0"
            )
            assert not await connection.scalar(
                text(
                    "SELECT has_column_privilege('app_user','public.ecu_inventory',"
                    "'security_version','UPDATE')"
                )
            )
            assert (
                await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_name='ecu_inventory' AND column_name='security_version'"
                    )
                )
                == 1
            )
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE alembic_version SET version_num='a05e127c349b'"))
        await engine.dispose()
