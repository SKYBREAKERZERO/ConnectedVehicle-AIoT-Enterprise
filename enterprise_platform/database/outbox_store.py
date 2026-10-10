from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
)

from enterprise_platform.database.repositories.outbox import (
    SQLAlchemyOutboxRepository,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from enterprise_platform.reliability.outbox import (
    ClaimedOutboxEvent,
)


class SQLAlchemyOutboxStore:
    """Provides short transactional boundaries for outbox operations."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._session_factory = session_factory

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)

            claimed = await repository.claim_batch(
                batch_size=batch_size,
                lease_seconds=lease_seconds,
                now=now,
            )

            await uow.commit()

            return claimed

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
    ) -> bool:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)

            updated = await repository.mark_published(
                outbox_id=outbox_id,
                claim_token=claim_token,
                published_at=published_at,
            )

            await uow.commit()

            return updated

    async def schedule_retry(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        available_at: datetime,
    ) -> bool:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)

            updated = await repository.schedule_retry(
                outbox_id=outbox_id,
                claim_token=claim_token,
                available_at=available_at,
            )

            await uow.commit()

            return updated

    async def mark_failed(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        failed_at: datetime,
        failure_code: str,
    ) -> bool:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            updated = await SQLAlchemyOutboxRepository(uow.session).mark_failed(
                outbox_id=outbox_id,
                claim_token=claim_token,
                failed_at=failed_at,
                failure_code=failure_code,
            )
            await uow.commit()
            return updated
