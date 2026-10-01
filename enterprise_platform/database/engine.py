from __future__ import annotations

from sqlalchemy import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from enterprise_platform.config.settings import Settings


def build_database_url(settings: Settings) -> URL:
    return URL.create(
        drivername="postgresql+asyncpg",
        username=settings.database_username,
        password=settings.database_password.get_secret_value(),
        host=settings.database_host,
        port=settings.database_port,
        database=settings.database_name,
    )


def create_database_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(
        build_database_url(settings),
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout_seconds,
        connect_args={
            "timeout": settings.database_connect_timeout_seconds,
        },
    )
