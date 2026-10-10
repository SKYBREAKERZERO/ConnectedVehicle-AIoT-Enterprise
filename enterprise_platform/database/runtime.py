from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DatabaseRuntime, load_runtime_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.session import create_session_factory


@asynccontextmanager
async def runtime_database_sessions(
    settings: Settings, runtime: DatabaseRuntime
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_database_engine(await load_runtime_database_settings(settings, runtime))
    try:
        yield create_session_factory(engine)
    finally:
        await engine.dispose()
