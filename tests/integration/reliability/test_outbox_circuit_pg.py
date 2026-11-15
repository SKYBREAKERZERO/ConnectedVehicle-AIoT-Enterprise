"""Real PostgreSQL outbox + Redis cross-worker circuit integration."""

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.repositories.outbox import SQLAlchemyOutboxRepository
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.reliability.circuit_breaker import (
    CircuitPolicy,
    RedisCircuitBreaker,
)
from enterprise_platform.reliability.outbox import ClaimedOutboxEvent, PendingOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


def redis_client() -> Redis:
    return Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "16379")),
        decode_responses=True,
    )


@pytest.mark.integration
async def test_cb003_half_open_single_probe_across_workers() -> None:
    first, second = redis_client(), redis_client()
    key = "cb-integration:" + uuid4().hex
    policy = CircuitPolicy(failure_threshold=1, open_seconds=1)
    a = RedisCircuitBreaker(first, key=key, policy=policy)
    b = RedisCircuitBreaker(second, key=key, policy=policy)
    try:
        await a.failure(await a.acquire())
        assert not (await b.acquire()).allowed
        await asyncio.sleep(1.1)
        acquired = await asyncio.gather(a.acquire(), b.acquire())
        assert sum(permit.allowed for permit in acquired) == 1
        assert sum(bool(permit.token) for permit in acquired) == 1
    finally:
        await first.delete(key)
        await first.aclose()
        await second.aclose()


@pytest.mark.integration
async def test_cb006_restart_restores_open_state() -> None:
    first, second = redis_client(), redis_client()
    key = "cb-restart:" + uuid4().hex
    policy = CircuitPolicy(failure_threshold=1, open_seconds=30)
    try:
        previous = RedisCircuitBreaker(first, key=key, policy=policy)
        await previous.failure(await previous.acquire())
        await first.aclose()
        restored = RedisCircuitBreaker(second, key=key, policy=policy)
        assert not (await restored.acquire()).allowed
    finally:
        await second.delete(key)
        await second.aclose()


@pytest.mark.integration
async def test_cb008_open_preserves_attempts_and_schedule() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    client = redis_client()
    key = "cb-outbox:" + uuid4().hex
    circuit = RedisCircuitBreaker(client, key=key, policy=CircuitPolicy(failure_threshold=1))
    event_id = "cb-test-" + uuid4().hex
    destination = "cb-destination-" + uuid4().hex
    event = create_event_envelope(
        event_id=event_id,
        event_type="vehicle.command.requested",
        source="cb-pg-integration",
        payload={"vehicle_id": "VIN-CB-001", "command": "lock"},
    )
    event_was_sent = False

    async def publisher(_event: object) -> None:
        nonlocal event_was_sent
        event_was_sent = True

    try:
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            SQLAlchemyOutboxRepository(uow.session).add(
                PendingOutboxEvent.from_event(event, destination=destination)
            )
            await uow.commit()
        await circuit.failure(await circuit.acquire())
        dispatcher = OutboxDispatcher(
            store=SQLAlchemyOutboxStore(sessions, destination=destination),
            destinations=MappingOutboxDestinationResolver({destination: publisher}),
            retry_policy=RetryPolicy(),
            circuit=circuit,
        )
        result = await dispatcher.dispatch_batch()
        assert result.claimed == 0
        assert not event_was_sent
        async with sessions() as session:
            row = (
                await session.execute(
                    select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
                )
            ).scalar_one()
            assert row.attempts == 0
            assert row.status == "pending"
            assert row.claim_token is None
            assert row.available_at <= datetime.now(UTC)
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
            )
        await client.delete(key)
        await client.aclose()
        await engine.dispose()


@pytest.mark.integration
async def test_cb009_runtime_role_isolation_pg17() -> None:
    engine = create_database_engine(get_settings())
    try:
        async with engine.connect() as connection:
            version = int(await connection.scalar(text("SHOW server_version_num")))
            assert 170000 <= version < 180000
            row = (
                await connection.execute(
                    text(
                        "SELECT rolsuper, rolbypassrls, rolcreaterole "
                        "FROM pg_roles WHERE rolname = 'outbox_worker'"
                    )
                )
            ).one()
            assert row == (False, False, False)
            can_select = await connection.scalar(
                text("SELECT has_table_privilege('outbox_worker', 'outbox_events', 'SELECT')")
            )
            can_delete = await connection.scalar(
                text("SELECT has_table_privilege('outbox_worker', 'outbox_events', 'DELETE')")
            )
            rls = await connection.scalar(
                text("SELECT relrowsecurity FROM pg_class WHERE oid='outbox_events'::regclass")
            )
            assert can_select is True and can_delete is False and rls is True
    finally:
        await engine.dispose()


class CountingOutboxStore(SQLAlchemyOutboxStore):
    def __init__(self, sessions: async_sessionmaker[AsyncSession], *, destination: str) -> None:
        super().__init__(sessions, destination=destination)
        self.claim_calls: list[int] = []
        self.last_claims: tuple[ClaimedOutboxEvent, ...] = ()

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        self.claim_calls.append(batch_size)
        self.last_claims = await super().claim_batch(
            batch_size=batch_size, lease_seconds=lease_seconds, now=now
        )
        return self.last_claims


@pytest.mark.integration
async def test_cost01_pg_closed_10_events_one_claim() -> None:
    """Use one PostgreSQL Claim transaction rather than ten under CLOSED."""
    engine = create_database_engine(get_settings())
    sessions = create_session_factory(engine)
    cache = redis_client()
    destination = "cost01-batch-" + uuid4().hex
    key = "cost01-circuit-" + uuid4().hex
    ids = ["cost01-" + uuid4().hex for _ in range(10)]
    baseline = datetime.now(UTC) - timedelta(minutes=2)
    store = CountingOutboxStore(sessions, destination=destination)
    circuit = RedisCircuitBreaker(cache, key=key, policy=CircuitPolicy())
    sent: list[str] = []

    async def publisher(event: EventEnvelope) -> None:
        sent.append(event.event_id)

    try:
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            for index, event_id in enumerate(ids):
                event = create_event_envelope(
                    event_id=event_id,
                    event_type="vehicle.command.requested",
                    source="cost01-pg",
                    payload={"vehicle_id": "VIN-COST01", "command": "lock"},
                )
                SQLAlchemyOutboxRepository(uow.session).add(
                    PendingOutboxEvent.from_event(
                        event,
                        destination=destination,
                        created_at=baseline + timedelta(milliseconds=index),
                        available_at=baseline,
                    )
                )
            await uow.commit()

        dispatcher = OutboxDispatcher(
            store=store,
            destinations=MappingOutboxDestinationResolver({destination: publisher}),
            retry_policy=RetryPolicy(max_attempts=5),
            batch_size=10,
            circuit=circuit,
        )
        result = await dispatcher.dispatch_batch()
        assert result.claimed == result.published == 10
        assert result.released_unattempted == result.stale_claims == 0
        assert store.claim_calls == [10]
        assert set(sent) == set(ids)
        async with sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 10
            assert all(row.status == "published" and row.attempts == 1 for row in rows)
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
            )
        await cache.delete(key)
        await cache.aclose()
        await engine.dispose()


@pytest.mark.integration
async def test_cost01_pg_open_refunds_remaining_without_retry_budget() -> None:
    """A real Redis OPEN stops the batch and refunds untouched PG attempts."""
    engine = create_database_engine(get_settings())
    sessions = create_session_factory(engine)
    cache = redis_client()
    destination = "cost01-fault-" + uuid4().hex
    key = "cost01-fault-circuit-" + uuid4().hex
    ids = ["cost01-fault-" + uuid4().hex for _ in range(5)]
    baseline = datetime.now(UTC) - timedelta(minutes=2)
    store = CountingOutboxStore(sessions, destination=destination)
    circuit = RedisCircuitBreaker(cache, key=key, policy=CircuitPolicy(failure_threshold=1))
    sent: list[str] = []

    async def publisher(event: EventEnvelope) -> None:
        sent.append(event.event_id)
        raise MessagePublishError()

    try:
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            for index, event_id in enumerate(ids):
                event = create_event_envelope(
                    event_id=event_id,
                    event_type="vehicle.command.requested",
                    source="cost01-fault-pg",
                    payload={"vehicle_id": "VIN-COST01", "command": "lock"},
                )
                SQLAlchemyOutboxRepository(uow.session).add(
                    PendingOutboxEvent.from_event(
                        event,
                        destination=destination,
                        created_at=baseline + timedelta(milliseconds=index),
                        available_at=baseline,
                    )
                )
            await uow.commit()

        result = await OutboxDispatcher(
            store=store,
            destinations=MappingOutboxDestinationResolver({destination: publisher}),
            retry_policy=RetryPolicy(max_attempts=5),
            batch_size=5,
            circuit=circuit,
        ).dispatch_batch()
        assert store.claim_calls == [5]
        assert result.claimed == 5
        assert result.retries_scheduled == 1
        assert result.released_unattempted == 4
        assert result.stale_claims == result.published == 0
        assert sent == [ids[0]]

        async with sessions() as session:
            rows = (
                (
                    await session.execute(
                        select(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
                    )
                )
                .scalars()
                .all()
            )
            lookup = {row.event_id: row for row in rows}
            assert lookup[ids[0]].attempts == 1
            assert lookup[ids[0]].status == "pending"
            for event_id in ids[1:]:
                row = lookup[event_id]
                assert row.attempts == 0
                assert row.status == "pending"
                assert row.claim_token is None and row.lease_expires_at is None

        async with SQLAlchemyUnitOfWork(sessions) as uow:
            stale = store.last_claims[1]
            assert not await SQLAlchemyOutboxRepository(uow.session).mark_published(
                outbox_id=stale.id,
                claim_token=stale.claim_token,
            )
            await uow.commit()
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
            )
        await cache.delete(key)
        await cache.aclose()
        await engine.dispose()


@pytest.mark.integration
async def test_cost01_pg_stale_token_cannot_refund_current_claim() -> None:
    """The refund API requires current token, live lease and PROCESSING."""
    engine = create_database_engine(get_settings())
    sessions = create_session_factory(engine)
    event_id = "cost01-token-" + uuid4().hex
    destination = "cost01-token-route-" + uuid4().hex
    try:
        event = create_event_envelope(
            event_id=event_id,
            event_type="vehicle.command.requested",
            source="cost01-fencing-pg",
            payload={"vehicle_id": "VIN-COST01", "command": "lock"},
        )
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            SQLAlchemyOutboxRepository(uow.session).add(
                PendingOutboxEvent.from_event(event, destination=destination)
            )
            await uow.commit()

        store = SQLAlchemyOutboxStore(sessions, destination=destination)
        claimed = await store.claim_batch(batch_size=1, lease_seconds=30)
        assert len(claimed) == 1
        stale = replace(claimed[0], claim_token=str(uuid4()))
        assert await store.release_unattempted(claims=(stale,)) == 0

        async with sessions() as session:
            row = (
                await session.execute(
                    select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
                )
            ).scalar_one()
            assert row.status == "processing"
            assert row.attempts == 1
            assert row.claim_token == claimed[0].claim_token

        assert await store.release_unattempted(claims=claimed) == 1
        assert await store.release_unattempted(claims=claimed) == 0
        async with sessions() as session:
            row = (
                await session.execute(
                    select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
                )
            ).scalar_one()
            assert row.status == "pending"
            assert row.attempts == 0
            assert row.claim_token is None
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
            )
        await engine.dispose()
