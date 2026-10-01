from __future__ import annotations

from types import TracebackType

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from enterprise_platform.database.exceptions import UnitOfWorkNotStartedError


class SQLAlchemyUnitOfWork:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None
        self._finished = False

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise UnitOfWorkNotStartedError(
                "Unit of work has not been started.",
            )

        return self._session

    async def __aenter__(self) -> SQLAlchemyUnitOfWork:
        if self._session is not None:
            raise RuntimeError("Unit of work is already active.")

        self._session = self._session_factory()
        self._finished = False

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        session = self._session

        if session is None:
            return

        try:
            if not self._finished:
                await session.rollback()
        finally:
            await session.close()
            self._session = None
            self._finished = False

    async def commit(self) -> None:
        session = self.session
        await session.commit()
        self._finished = True

    async def rollback(self) -> None:
        session = self.session
        await session.rollback()
        self._finished = True
