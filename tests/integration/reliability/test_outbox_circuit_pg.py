"""Real PostgreSQL outbox + Redis cross-worker circuit integration."""

import asyncio
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import delete, select, text

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.repositories.outbox import SQLAlchemyOutboxRepository
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.reliability.circuit_breaker import (
    CircuitPolicy,
    RedisCircuitBreaker,
)
from enterprise_platform.reliability.outbox import PendingOutboxEvent
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
    circuit = RedisCircuitBreaker(
        client, key=key, policy=CircuitPolicy(failure_threshold=1)
    )
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
