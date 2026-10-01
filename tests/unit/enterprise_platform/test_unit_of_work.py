from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise_platform.database.exceptions import UnitOfWorkNotStartedError
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork


def test_session_is_unavailable_before_unit_of_work_starts() -> None:
    session_factory = Mock()
    unit_of_work = SQLAlchemyUnitOfWork(session_factory)

    with pytest.raises(UnitOfWorkNotStartedError):
        _ = unit_of_work.session


async def test_unit_of_work_commit_commits_and_closes_session() -> None:
    session = AsyncMock(spec=AsyncSession)
    session_factory = Mock(return_value=session)

    unit_of_work = SQLAlchemyUnitOfWork(session_factory)

    async with unit_of_work:
        assert unit_of_work.session is session
        await unit_of_work.commit()

    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()
    session.close.assert_awaited_once()


async def test_unit_of_work_rolls_back_uncommitted_work() -> None:
    session = AsyncMock(spec=AsyncSession)
    session_factory = Mock(return_value=session)

    unit_of_work = SQLAlchemyUnitOfWork(session_factory)

    async with unit_of_work:
        assert unit_of_work.session is session

    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()
    session.close.assert_awaited_once()


async def test_unit_of_work_rolls_back_when_exception_occurs() -> None:
    session = AsyncMock(spec=AsyncSession)
    session_factory = Mock(return_value=session)

    unit_of_work = SQLAlchemyUnitOfWork(session_factory)

    with pytest.raises(RuntimeError, match="transaction failed"):
        async with unit_of_work:
            raise RuntimeError("transaction failed")

    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()
    session.close.assert_awaited_once()


async def test_explicit_rollback_is_not_repeated_on_exit() -> None:
    session = AsyncMock(spec=AsyncSession)
    session_factory = Mock(return_value=session)

    unit_of_work = SQLAlchemyUnitOfWork(session_factory)

    async with unit_of_work:
        await unit_of_work.rollback()

    session.rollback.assert_awaited_once()
    session.close.assert_awaited_once()
