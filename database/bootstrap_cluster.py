"""Explicit cluster-role bootstrap; Schema migration uses a different non-superuser."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol, cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    bootstrap_database_settings,
    migration_database_settings,
)
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.management_identity import verify_bootstrap_identity


class SQLDriver(Protocol):
    async def execute(self, query: str) -> str: ...


async def check_bootstrap(connection: AsyncConnection, settings: Settings) -> None:
    principal = bootstrap_database_settings(settings).database_username
    await connection.run_sync(lambda sync: verify_bootstrap_identity(sync, principal))


async def bootstrap(settings: Settings) -> None:
    migration = migration_database_settings(settings)
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.begin() as connection:
            await check_bootstrap(connection, settings)
            role = await connection.scalar(
                text("SELECT quote_ident(:role)"), {"role": migration.database_username}
            )
            driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
            exists = await connection.scalar(
                text("SELECT 1 FROM pg_roles WHERE rolname=:role"),
                {"role": migration.database_username},
            )
            if not exists:
                await driver.execute(f"CREATE ROLE {role} LOGIN")
            await driver.execute(
                f"ALTER ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS "
                "NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
            )
            password = await connection.scalar(
                text("SELECT quote_literal(:value)"),
                {"value": migration.database_password.get_secret_value()},
            )
            await driver.execute(f"ALTER ROLE {role} PASSWORD {password}")
            owner = await connection.scalar(
                text(
                    "SELECT pg_get_userbyid(datdba) FROM pg_database "
                    "WHERE datname=current_database()"
                )
            )
            if owner != migration.database_username:
                populated = await connection.scalar(
                    text(
                        "SELECT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n "
                        "ON n.oid=c.relnamespace WHERE n.nspname='public' "
                        "AND c.relkind IN ('r','p','S','v','m'))"
                    )
                )
                if populated:
                    raise ValueError(
                        "Existing database ownership requires a reviewed explicit cutover"
                    )
                database = await connection.scalar(text("SELECT quote_ident(current_database())"))
                await driver.execute(f"ALTER DATABASE {database} OWNER TO {role}")
            await driver.execute(Path(__file__).with_name("runtime-roles.sql").read_text())
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(bootstrap(Settings()))
