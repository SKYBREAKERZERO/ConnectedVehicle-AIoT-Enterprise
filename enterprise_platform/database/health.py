from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine


class DatabaseHealthFailure(StrEnum):
    TIMEOUT = "timeout"
    DATABASE_ERROR = "database_error"


@dataclass(frozen=True, slots=True)
class DatabaseHealthResult:
    healthy: bool
    failure: DatabaseHealthFailure | None = None


async def check_database_health(
    engine: AsyncEngine,
    timeout_seconds: float,
) -> DatabaseHealthResult:
    try:
        async with asyncio.timeout(timeout_seconds):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
    except TimeoutError:
        return DatabaseHealthResult(
            healthy=False,
            failure=DatabaseHealthFailure.TIMEOUT,
        )
    except SQLAlchemyError:
        return DatabaseHealthResult(
            healthy=False,
            failure=DatabaseHealthFailure.DATABASE_ERROR,
        )

    return DatabaseHealthResult(healthy=True)
