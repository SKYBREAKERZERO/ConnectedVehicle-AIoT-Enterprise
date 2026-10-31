"""Bounded retries for whole, rolled-back campaign transactions."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable

from sqlalchemy.exc import DBAPIError

from enterprise_platform.errors.base import ConflictError, DependencyUnavailableError

RETRYABLE = {
    "55P03": "lock_timeout",
    "40P01": "deadlock",
    "40001": "serialization_failure",
    "57014": "statement_timeout",
    "08003": "connection_lost",
    "08006": "connection_lost",
}


class CampaignLeaseLost(ConflictError):
    """The caller must stop; a different dispatcher may now own this campaign."""


class CampaignDatabaseBusy(DependencyUnavailableError):
    def __init__(self, sqlstate: str, attempts: int) -> None:
        self.sqlstate = sqlstate
        self.attempts = attempts
        super().__init__(f"Campaign database {RETRYABLE[sqlstate]} after {attempts} attempts")


async def database_retry[T](operation: Callable[[], Awaitable[T]]) -> T:
    # Reuse the operation ID/payload across attempts. Never retry inside a failed
    # transaction, or convert transient contention into a durable campaign pause.
    for attempt in range(1, 4):
        try:
            return await operation()
        except DBAPIError as exc:
            state = getattr(exc.orig, "sqlstate", None)
            if state not in RETRYABLE:
                raise
            if attempt == 3:
                raise CampaignDatabaseBusy(state, attempt) from exc
            await asyncio.sleep(random.uniform(0.025, 0.05) * 2 ** (attempt - 1))
    raise AssertionError("Unreachable retry state")
