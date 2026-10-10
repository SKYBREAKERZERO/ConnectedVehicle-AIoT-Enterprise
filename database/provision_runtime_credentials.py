"""Controlled provisioning: python -m database.provision_runtime_credentials."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Protocol, cast

from sqlalchemy import text

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS, migration_database_settings
from enterprise_platform.database.engine import create_database_engine


class SecretWriter(Protocol):
    def put_secret_value(self, *, SecretId: str, SecretString: str) -> object: ...


class SQLDriver(Protocol):
    async def execute(self, query: str) -> str: ...


async def provision(settings: Settings) -> None:
    passwords = {
        runtime: os.environ[f"{user.upper()}_PASSWORD"] for runtime, user in DATABASE_USERS.items()
    }
    if any(not password for password in passwords.values()) or len(set(passwords.values())) != 3:
        raise ValueError("Provide three nonempty, distinct runtime passwords")
    admin = migration_database_settings(settings)
    if admin.migration_database_password is not None and (
        admin.migration_database_password.get_secret_value() in passwords.values()
    ):
        raise ValueError("Runtime passwords must differ from the migration password")
    engine = create_database_engine(admin)
    try:
        async with engine.begin() as connection:
            raw = await connection.get_raw_connection()
            driver = cast(SQLDriver, raw.driver_connection)
            await driver.execute(Path(__file__).with_name("runtime-grants.sql").read_text())
            for runtime, user in DATABASE_USERS.items():
                # PostgreSQL utility statements cannot bind passwords. Server-side
                # quote_literal safely handles every password character.
                quoted = await connection.scalar(
                    text("SELECT quote_literal(:password)"), {"password": passwords[runtime]}
                )
                await driver.execute(f"ALTER ROLE {user} PASSWORD {quoted}")
    finally:
        await engine.dispose()
    client = cast(SecretWriter, AWSClientFactory(settings).secrets_manager())
    for runtime, user in DATABASE_USERS.items():
        secret_id = {
            "application": settings.application_database_secret_id,
            "outbox": settings.outbox_database_secret_id,
            "remote-command": settings.remote_command_database_secret_id,
        }[
            runtime
        ] or f"{settings.database_secret_prefix}/{settings.app_env.value}/database/{runtime}"
        payload = json.dumps(
            {
                "engine": "postgres",
                "host": settings.database_host,
                "port": settings.database_port,
                "dbname": settings.database_name,
                "username": user,
                "password": passwords[runtime],
            }
        )
        await asyncio.to_thread(client.put_secret_value, SecretId=secret_id, SecretString=payload)


if __name__ == "__main__":
    asyncio.run(provision(Settings()))
