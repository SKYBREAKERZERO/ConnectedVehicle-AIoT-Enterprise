"""Bounded transaction retries; uncertain commits require durable reconciliation."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from contextlib import suppress

from sqlalchemy.exc import DBAPIError

logger = logging.getLogger(__name__)


def record_recovery(state: str, attempt: int, code: str | None = None) -> None:
    with suppress(Exception):
        logger.warning(
            "database_transaction_recovery state=%s attempt=%s sqlstate=%s",
            state,
            attempt,
            code,
            extra={
                "recovery_state": state,
                "attempt": attempt,
                "sqlstate": code,
            },
        )


class CommitOutcomeUnknown(RuntimeError):
    """The server may have committed; do not replay before reconciliation."""


def sqlstate(error: BaseException) -> str | None:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "sqlstate", None) or getattr(current, "pgcode", None)
        if isinstance(value, str):
            return value
        current = getattr(current, "orig", None) or current.__cause__
    return None


def connection_lost(error: BaseException) -> bool:
    code = sqlstate(error)
    return (
        isinstance(error, (TimeoutError, ConnectionError))
        or isinstance(error, DBAPIError)
        and error.connection_invalidated
        or code is not None
        and (code.startswith("08") or code in {"57P01", "57P02", "57P03"})
    )


async def recover_transaction[T](
    operation: Callable[[], Awaitable[T]],
    reconcile: Callable[[], Awaitable[T | None]],
    *,
    max_attempts: int = 3,
    base_delay: float = 0.1,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Each operation invocation must own a fresh transaction and have no external I/O.

    Only PostgreSQL-confirmed transaction aborts are replayed. A missing durable
    result after an uncertain commit is not proof of rollback: escalate instead.
    """
    if not 1 <= max_attempts <= 10 or not 0 < base_delay <= 10:
        raise ValueError("Invalid transaction recovery bounds")
    for attempt in range(max_attempts):
        try:
            return await operation()
        except CommitOutcomeUnknown as exc:
            record_recovery("RECONCILE", attempt + 1)
            try:
                async with asyncio.timeout(10):
                    result = await reconcile()
            except Exception as lookup_error:
                record_recovery("ESCALATED", attempt + 1)
                raise CommitOutcomeUnknown("Commit reconciliation unavailable") from lookup_error
            if result is None:
                record_recovery("ESCALATED", attempt + 1)
                raise CommitOutcomeUnknown("Commit unresolved; reconciliation required") from exc
            record_recovery("RECOVERED", attempt + 1)
            return result
        except DBAPIError as exc:
            code = sqlstate(exc)
            if code not in {"40P01", "40001", "55P03"} or attempt + 1 == max_attempts:
                record_recovery("ESCALATED", attempt + 1, code)
                raise
            record_recovery("RETRY", attempt + 1, code)
            await sleep(min(2.0, base_delay * 2**attempt) * random.uniform(0.5, 1.0))
    raise AssertionError("Unreachable recovery state")
