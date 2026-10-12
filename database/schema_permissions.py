"""Separate cluster role management from migration-owner table/function grants."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from sqlalchemy import text

from database.bootstrap_cluster import SQLDriver, check_bootstrap
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    DatabaseRuntime,
    bootstrap_database_settings,
    migration_database_settings,
)
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.management_identity import verify_migration_identity
from enterprise_platform.database.migration_guard import MIGRATION_LOCK_KEY


def runtime_sql(filename: str, roles: dict[DatabaseRuntime, str]) -> str:
    sql = Path(__file__).with_name(filename).read_text(encoding="utf-8")
    for runtime, original in DATABASE_USERS.items():
        sql = sql.replace(original, roles[runtime])
    return sql


async def prepare_roles(settings: Settings, roles: dict[DatabaseRuntime, str]) -> None:
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.begin() as connection:
            await check_bootstrap(connection, settings)
            driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
            await driver.execute(runtime_sql("runtime-roles.sql", roles))
    finally:
        await engine.dispose()


async def grant_runtimes(
    settings: Settings, roles: dict[DatabaseRuntime, str], tenant: str | None = None
) -> None:
    migration = migration_database_settings(settings)
    engine = create_database_engine(migration)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync: verify_migration_identity(sync, migration.database_username)
            )
            await connection.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY}
            )
            driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
            await driver.execute(runtime_sql("runtime-grants.sql", roles))
            if tenant is not None:
                for role in roles.values():
                    previous = await connection.scalar(
                        text(
                            "SELECT tenant_id FROM public.runtime_tenant_bindings "
                            "WHERE role_name=:role"
                        ),
                        {"role": role},
                    )
                    if previous is not None and previous != tenant:
                        raise ValueError("Existing role tenant binding conflicts")
                    await connection.execute(
                        text(
                            "INSERT INTO public.runtime_tenant_bindings VALUES (:role,:tenant) "
                            "ON CONFLICT DO NOTHING"
                        ),
                        {"role": role, "tenant": tenant},
                    )
    finally:
        await engine.dispose()
