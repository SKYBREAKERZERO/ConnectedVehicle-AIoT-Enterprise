from __future__ import annotations

from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.database.lifecycle import dispose_database_engine


async def test_dispose_database_engine_disposes_engine() -> None:
    engine = AsyncMock(spec=AsyncEngine)

    await dispose_database_engine(engine)

    engine.dispose.assert_awaited_once_with()
