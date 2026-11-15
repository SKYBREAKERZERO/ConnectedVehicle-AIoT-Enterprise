"""Cost-02: real Redis fleet-wide permits and PostgreSQL/LocalStack retry deferral."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from mypy_boto3_sqs.client import SQSClient as BotoSQSClient
from redis.asyncio import Redis
from sqlalchemy import delete, select, update

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.repositories.outbox import SQLAlchemyOutboxRepository
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.messaging.sqs import SQSClient, SQSEventQueue
from enterprise_platform.reliability.circuit_breaker import CircuitPolicy, RedisCircuitBreaker
from enterprise_platform.reliability.outbox import PendingOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.reliability.retry_budget import RedisRetryBudget, RetryBudgetPolicy


def redis_client() -> Redis:
    return Redis(
        host=os.environ.get("REDIS_HOST", "127.0.0.1"),
        port=int(os.environ.get("REDIS_PORT", "16379")),
        decode_responses=True,
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cost02_real_redis_multiworker_atomic_global_cap() -> None:
    first, second = redis_client(), redis_client()
    key = "cost02-atomic-" + uuid4().hex
    policy = RetryBudgetPolicy(rate_per_second=0.001, burst=5)
    a = RedisRetryBudget(first, key=key, policy=policy)
    b = RedisRetryBudget(second, key=key, policy=policy)
    try:
        permits = await asyncio.gather(
            *(a.acquire() if index % 2 else b.acquire() for index in range(50))
        )
        assert sum(permits) == 5
        assert set(permits) <= {0, 1}
        assert await a.acquire(5) == 0
        assert await b.acquire(5) == 0
    finally:
        await first.delete(key)
        await first.aclose()
        await second.aclose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cost02_real_pg_redis_localstack_fleet_retry_defers_without_attempt_loss() -> None:
    assert os.environ.get("AWS_ENDPOINT_URL") == "http://127.0.0.1:4566"
    engine = create_database_engine(get_settings())
    sessions = create_session_factory(engine)
    redis_a, redis_b = redis_client(), redis_client()
    sqs: BotoSQSClient = boto3.client(
        "sqs",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name="us-east-1",
        config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}),
    )
    ident = "cost02-" + uuid4().hex
    destination = ident
    queue_url = sqs.create_queue(QueueName=ident)["QueueUrl"]
    budget_key = ident + "-budget"
    circuit_key = ident + "-circuit"
    ids = [ident + "-" + str(i) for i in range(6)]
    try:
        base = datetime.now(UTC) - timedelta(minutes=2)
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)
            for i, event_id in enumerate(ids):
                event = create_event_envelope(
                    event_id=event_id,
                    event_type="vehicle.command.requested",
                    source="cost02-fleet-runtime",
                    payload={"vehicle_id": "VIN-COST02", "command": "lock"},
                )
                repository.add(
                    PendingOutboxEvent.from_event(
                        event,
                        destination=destination,
                        created_at=base + timedelta(microseconds=i),
                        available_at=base,
                    )
                )
            await uow.session.flush()
            await uow.session.execute(
                update(OutboxEventModel)
                .where(OutboxEventModel.event_id.in_(ids))
                .values(attempts=1)
            )
            await uow.commit()

        queue = SQSEventQueue(cast(SQSClient, cast(Any, sqs)), queue_url=queue_url)
        budget_policy = RetryBudgetPolicy(rate_per_second=0.001, burst=2, defer_seconds=20)
        store_a = SQLAlchemyOutboxStore(sessions, destination=destination)
        store_b = SQLAlchemyOutboxStore(sessions, destination=destination)

        def worker(store: SQLAlchemyOutboxStore, redis: Redis) -> OutboxDispatcher:
            return OutboxDispatcher(
                store=store,
                destinations=MappingOutboxDestinationResolver({destination: queue.send_event}),
                retry_policy=RetryPolicy(max_attempts=5),
                batch_size=3,
                lease_seconds=60,
                circuit=RedisCircuitBreaker(redis, key=circuit_key, policy=CircuitPolicy()),
                batch_publisher=queue.send_events_batch,
                batch_mark_published=store.mark_published_batch,
                batch_destination=destination,
                retry_budget=RedisRetryBudget(redis, key=budget_key, policy=budget_policy),
                retry_deferrer=store.defer_unattempted,
            )

        a = worker(store_a, redis_a)
        b = worker(store_b, redis_b)
        result_a, result_b = await asyncio.gather(a.dispatch_batch(), b.dispatch_batch())
        assert result_a.claimed + result_b.claimed == 6
        assert result_a.published + result_b.published == 2
        assert result_a.retry_budget_deferred + result_b.retry_budget_deferred == 4
        assert result_a.stale_claims + result_b.stale_claims == 0

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
            assert len(rows) == 6
            published = [r for r in rows if r.status == "published"]
            deferred = [r for r in rows if r.status == "pending"]
            assert len(published) == 2 and len(deferred) == 4
            assert all(row.attempts == 2 for row in published)
            assert all(row.attempts == 1 for row in deferred)
            assert all(row.available_at > datetime.now(UTC) for row in deferred)
            assert all(row.claim_token is None and row.lease_expires_at is None for row in rows)

        assert (await a.dispatch_batch()).claimed == 0
        assert (await b.dispatch_batch()).claimed == 0
        received: set[str] = set()
        for _ in range(4):
            messages = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            ).get("Messages", [])
            for message in messages:
                payload = json.loads(message["Body"])
                assert isinstance(payload, dict)
                received_id = payload.get("event_id")
                assert isinstance(received_id, str)
                received.add(received_id)
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            if len(received) == 2:
                break
        assert len(received) == 2
        assert received == {row.event_id for row in published}
        print(
            "COST02_FLEET_REAL=workers:2 retries:6 granted:2 deferred:4 "
            "attempt_refund:4 redis_global:1",
            flush=True,
        )
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
            )
        await redis_a.delete(budget_key, circuit_key)
        await redis_a.aclose()
        await redis_b.aclose()
        sqs.delete_queue(QueueUrl=queue_url)
        sqs.close()
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cost02_real_pg_stale_claim_cannot_defer_or_refund() -> None:
    engine = create_database_engine(get_settings())
    sessions = create_session_factory(engine)
    ident = "cost02-fence-" + uuid4().hex
    event = create_event_envelope(
        event_id=ident,
        event_type="vehicle.command.requested",
        source="cost02-fencing",
        payload={"vehicle_id": "VIN-COST02", "command": "lock"},
    )
    store = SQLAlchemyOutboxStore(sessions, destination=ident)
    try:
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            SQLAlchemyOutboxRepository(uow.session).add(
                PendingOutboxEvent.from_event(event, destination=ident)
            )
            await uow.commit()
        claimed = await store.claim_batch(batch_size=1, lease_seconds=30)
        assert len(claimed) == 1 and claimed[0].attempts == 1
        stale = replace(claimed[0], claim_token=str(uuid4()))
        delay = datetime.now(UTC) + timedelta(seconds=20)
        assert await store.defer_unattempted(claims=(stale,), available_at=delay) == 0
        assert await store.defer_unattempted(claims=claimed, available_at=delay) == 1
        assert await store.defer_unattempted(claims=claimed, available_at=delay) == 0
        async with sessions() as session:
            row = (
                await session.execute(
                    select(OutboxEventModel).where(OutboxEventModel.event_id == ident)
                )
            ).scalar_one()
            assert row.status == "pending" and row.attempts == 0
            assert row.claim_token is None and row.lease_expires_at is None
            assert row.available_at >= delay
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id == ident)
            )
        await engine.dispose()
