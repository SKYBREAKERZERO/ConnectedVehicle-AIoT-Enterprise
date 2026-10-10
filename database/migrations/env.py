from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from connected_vehicle import device_data as _device_data  # noqa: F401
from connected_vehicle.remote_command.persistence import (
    models as _remote_command_models,  # noqa: F401
)
from connected_vehicle.vehicle.persistence import models as _vehicle_models  # noqa: F401
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database import models as _models  # noqa: F401
from enterprise_platform.database.base import Base
from enterprise_platform.database.credentials import migration_database_settings
from enterprise_platform.database.engine import build_database_url

target_metadata = Base.metadata


def run_migrations_with_connection(
    connection: Connection,
) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    settings = migration_database_settings(get_settings())
    database_url = build_database_url(settings)

    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named",
        },
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    settings = migration_database_settings(get_settings())

    engine = create_async_engine(
        build_database_url(settings),
        poolclass=pool.NullPool,
        connect_args={
            "timeout": settings.database_connect_timeout_seconds,
        },
    )

    try:
        async with engine.connect() as connection:
            await connection.run_sync(run_migrations_with_connection)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
