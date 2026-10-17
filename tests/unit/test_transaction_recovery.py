from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise_platform.database.recovery import (
    CommitOutcomeUnknown,
    recover_transaction,
    sqlstate,
)
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork


def database_error(code: str) -> DBAPIError:
    error = Exception("sanitized fixture")
    error.sqlstate = code  # type: ignore[attr-defined]
    return DBAPIError(None, None, error)


@pytest.mark.parametrize("code", ["40P01", "40001", "55P03"])
async def test_confirmed_abort_retries_fresh_transaction_with_bounded_backoff(
    code: str, caplog: pytest.LogCaptureFixture
) -> None:
    operation = AsyncMock(side_effect=[database_error(code), database_error(code), "done"])
    lookup = AsyncMock()
    sleep = AsyncMock()
    assert await recover_transaction(operation, lookup, sleep=sleep) == "done"
    assert operation.await_count == 3
    assert sleep.await_count == 2
    assert all(0 < call.args[0] <= 0.2 for call in sleep.await_args_list)
    lookup.assert_not_awaited()
    assert any(f"sqlstate={code}" in entry.getMessage() for entry in caplog.records)


@pytest.mark.parametrize("code", ["23505", "42501", "08006", "57014"])
async def test_other_failures_are_not_blindly_retried(code: str) -> None:
    operation = AsyncMock(side_effect=database_error(code))
    with pytest.raises(DBAPIError):
        await recover_transaction(operation, AsyncMock())
    assert operation.await_count == 1


async def test_retry_budget_exhausts() -> None:
    operation = AsyncMock(side_effect=database_error("40P01"))
    with pytest.raises(DBAPIError):
        await recover_transaction(operation, AsyncMock(), sleep=AsyncMock())
    assert operation.await_count == 3


@pytest.mark.parametrize("found", [None, "durable-result"])
async def test_unknown_commit_reads_durable_result_without_replaying(found: str | None) -> None:
    operation = AsyncMock(side_effect=CommitOutcomeUnknown())
    lookup = AsyncMock(return_value=found)
    if found is None:
        with pytest.raises(CommitOutcomeUnknown, match="unresolved"):
            await recover_transaction(operation, lookup)
    else:
        assert await recover_transaction(operation, lookup) == found
    operation.assert_awaited_once()
    lookup.assert_awaited_once()


async def test_failed_reconciliation_stays_unknown() -> None:
    with pytest.raises(CommitOutcomeUnknown, match="unavailable"):
        await recover_transaction(
            AsyncMock(side_effect=CommitOutcomeUnknown()),
            AsyncMock(side_effect=ConnectionError()),
        )


@pytest.mark.parametrize("cleanup", ["rollback", "close"])
async def test_commit_disconnect_preserves_unknown_despite_rollback_failure(cleanup: str) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.commit.side_effect = ConnectionError("private connection details")
    getattr(session, cleanup).side_effect = ConnectionError()
    with pytest.raises(CommitOutcomeUnknown, match="acknowledgement"):
        async with SQLAlchemyUnitOfWork(Mock(return_value=session)) as work:
            await work.commit()
    session.close.assert_awaited_once()


def test_sqlstate_handles_exception_cycles() -> None:
    error = RuntimeError()
    error.__cause__ = error
    assert sqlstate(error) is None
