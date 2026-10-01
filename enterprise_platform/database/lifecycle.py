from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine


async def dispose_database_engine(engine: AsyncEngine) -> None:
    await engine.dispose()
