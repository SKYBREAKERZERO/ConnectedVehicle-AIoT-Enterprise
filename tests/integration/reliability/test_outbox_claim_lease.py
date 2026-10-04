from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import (
    create_database_engine,
)
from enterprise_platform.database.models.outbox import (
    OutboxEventModel,
)
from enterprise_platform.database.repositories.outbox import (
    SQLAlchemyOutboxRepository,
)
from enterprise_platform.database.session import (
    create_session_factory,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.reliability.outbox import (
    OutboxStatus,
    PendingOutboxEvent,
)


async def seed_events(
    session_factory: async_sessionmaker[AsyncSession],
    event_ids: list[str],
    *,
    timestamp: datetime,
) -> None:
    async with SQLAlchemyUnitOfWork(session_factory) as uow:
        repository = SQLAlchemyOutboxRepository(uow.session)

        for event_id in event_ids:
            event = create_event_envelope(
                event_id=event_id,
                event_type="vehicle.command.requested",
                source="outbox-claim-integration",
                payload={
                    "vehicle_id": f"VIN-{event_id[-8:]}",
                    "command": "lock",
                },
            )

            repository.add(
                PendingOutboxEvent.from_event(
                    event,
                    destination="vehicle-command",
                    created_at=timestamp,
                    available_at=timestamp,
                )
            )

        await uow.commit()


async def cleanup_events(
    engine: AsyncEngine,
    event_ids: list[str],
) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(event_ids))
        )


async def read_event_state(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_id: str,
) -> tuple[
    str,
    int,
    str | None,
    datetime | None,
    datetime | None,
]:
    async with session_factory() as session:
        result = await session.execute(
            select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
        )

        model = result.scalar_one()

        return (
            model.status,
            model.attempts,
            model.claim_token,
            model.lease_expires_at,
            model.published_at,
        )


@pytest.mark.asyncio
async def test_two_workers_claim_disjoint_batches_with_skip_locked() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    base_time = datetime(
        2000,
        1,
        1,
        tzinfo=UTC,
    )
    claim_time = base_time + timedelta(hours=1)

    event_ids = [f"skip-locked-{uuid4()}" for _ in range(10)]

    await seed_events(
        session_factory,
        event_ids,
        timestamp=base_time,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as worker_a:
            repository_a = SQLAlchemyOutboxRepository(worker_a.session)

            claimed_a = await repository_a.claim_batch(
                batch_size=5,
                lease_seconds=30,
                now=claim_time,
            )

            assert len(claimed_a) == 5

            # Persist PROCESSING state while deliberately keeping
            # Worker A's transaction and row locks open.
            await worker_a.session.flush()

            async with SQLAlchemyUnitOfWork(session_factory) as worker_b:
                repository_b = SQLAlchemyOutboxRepository(worker_b.session)

                claimed_b = await repository_b.claim_batch(
                    batch_size=5,
                    lease_seconds=30,
                    now=claim_time,
                )

                assert len(claimed_b) == 5

                ids_a = {claimed.event_id for claimed in claimed_a}
                ids_b = {claimed.event_id for claimed in claimed_b}

                assert ids_a.isdisjoint(ids_b)
                assert ids_a | ids_b == set(event_ids)

                assert all(claimed.attempts == 1 for claimed in claimed_a)
                assert all(claimed.attempts == 1 for claimed in claimed_b)

                await worker_b.commit()

            await worker_a.commit()

    finally:
        await cleanup_events(
            engine,
            event_ids,
        )
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_lease_is_reclaimed_and_stale_token_is_fenced() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    base_time = datetime(
        2001,
        1,
        1,
        tzinfo=UTC,
    )

    first_claim_time = base_time + timedelta(seconds=1)
    reclaim_time = base_time + timedelta(seconds=32)
    published_at = base_time + timedelta(seconds=33)

    event_id = f"lease-reclaim-{uuid4()}"
    event_ids = [event_id]

    await seed_events(
        session_factory,
        event_ids,
        timestamp=base_time,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as worker_a:
            repository_a = SQLAlchemyOutboxRepository(worker_a.session)

            first_claim = await repository_a.claim_batch(
                batch_size=1,
                lease_seconds=30,
                now=first_claim_time,
            )

            assert len(first_claim) == 1
            assert first_claim[0].event_id == event_id
            assert first_claim[0].attempts == 1

            await worker_a.commit()

        stale_claim = first_claim[0]

        async with SQLAlchemyUnitOfWork(session_factory) as worker_b:
            repository_b = SQLAlchemyOutboxRepository(worker_b.session)

            second_claim = await repository_b.claim_batch(
                batch_size=1,
                lease_seconds=30,
                now=reclaim_time,
            )

            assert len(second_claim) == 1
            assert second_claim[0].id == stale_claim.id
            assert second_claim[0].event_id == event_id
            assert second_claim[0].attempts == 2
            assert second_claim[0].claim_token != stale_claim.claim_token

            await worker_b.commit()

        current_claim = second_claim[0]

        async with SQLAlchemyUnitOfWork(session_factory) as stale_worker:
            stale_repository = SQLAlchemyOutboxRepository(stale_worker.session)

            stale_result = await stale_repository.mark_published(
                outbox_id=stale_claim.id,
                claim_token=stale_claim.claim_token,
                published_at=published_at,
            )

            assert stale_result is False

            await stale_worker.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as current_worker:
            current_repository = SQLAlchemyOutboxRepository(current_worker.session)

            publish_result = await current_repository.mark_published(
                outbox_id=current_claim.id,
                claim_token=current_claim.claim_token,
                published_at=published_at,
            )

            assert publish_result is True

            await current_worker.commit()

        (
            status,
            attempts,
            claim_token,
            lease_expires_at,
            stored_published_at,
        ) = await read_event_state(
            session_factory,
            event_id=event_id,
        )

        assert status == OutboxStatus.PUBLISHED.value
        assert attempts == 2
        assert claim_token is None
        assert lease_expires_at is None
        assert stored_published_at == published_at

    finally:
        await cleanup_events(
            engine,
            event_ids,
        )
        await engine.dispose()


@pytest.mark.asyncio
async def test_scheduled_retry_is_not_claimed_before_available_at() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    base_time = datetime(
        2002,
        1,
        1,
        tzinfo=UTC,
    )

    first_claim_time = base_time + timedelta(seconds=1)
    retry_available_at = base_time + timedelta(seconds=61)

    event_id = f"scheduled-retry-{uuid4()}"
    event_ids = [event_id]

    await seed_events(
        session_factory,
        event_ids,
        timestamp=base_time,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as worker:
            repository = SQLAlchemyOutboxRepository(worker.session)

            claimed = await repository.claim_batch(
                batch_size=1,
                lease_seconds=30,
                now=first_claim_time,
            )

            assert len(claimed) == 1
            assert claimed[0].attempts == 1

            await worker.commit()

        first_claim = claimed[0]

        async with SQLAlchemyUnitOfWork(session_factory) as retry_scheduler:
            repository = SQLAlchemyOutboxRepository(retry_scheduler.session)

            scheduled = await repository.schedule_retry(
                outbox_id=first_claim.id,
                claim_token=first_claim.claim_token,
                available_at=retry_available_at,
            )

            assert scheduled is True

            await retry_scheduler.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as early_worker:
            repository = SQLAlchemyOutboxRepository(early_worker.session)

            early_claim = await repository.claim_batch(
                batch_size=1,
                lease_seconds=30,
                now=retry_available_at - timedelta(seconds=1),
            )

            assert early_claim == ()

            await early_worker.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as retry_worker:
            repository = SQLAlchemyOutboxRepository(retry_worker.session)

            retry_claim = await repository.claim_batch(
                batch_size=1,
                lease_seconds=30,
                now=retry_available_at,
            )

            assert len(retry_claim) == 1
            assert retry_claim[0].event_id == event_id
            assert retry_claim[0].attempts == 2

            await retry_worker.commit()

    finally:
        await cleanup_events(
            engine,
            event_ids,
        )
        await engine.dispose()
