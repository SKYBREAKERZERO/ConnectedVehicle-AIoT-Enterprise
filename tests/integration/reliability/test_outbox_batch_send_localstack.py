"""Cost-01C end-to-end: real PostgreSQL 17, Redis and LocalStack SQS."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from mypy_boto3_sqs.client import SQSClient as BotoSQSClient
from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.repositories.outbox import SQLAlchemyOutboxRepository
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.messaging.sqs import (
    SQSBatchSendResponse,
    SQSEventQueue,
)
from enterprise_platform.messaging.sqs import (
    SQSClient as TransportClient,
)
from enterprise_platform.reliability.circuit_breaker import CircuitPolicy, RedisCircuitBreaker
from enterprise_platform.reliability.outbox import ClaimedOutboxEvent, PendingOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


class CountingBatchClient:
    def __init__(self, client: BotoSQSClient) -> None:
        self.client = client
        self.batch_calls = 0
        self.single_calls = 0

    def send_message_batch(
        self, *, QueueUrl: str, Entries: list[dict[str, str]]
    ) -> SQSBatchSendResponse:
        self.batch_calls += 1
        return cast(
            SQSBatchSendResponse,
            self.client.send_message_batch(QueueUrl=QueueUrl, Entries=Entries),
        )

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, str]:
        self.single_calls += 1
        return cast(
            dict[str, str],
            self.client.send_message(QueueUrl=QueueUrl, MessageBody=MessageBody),
        )


class CountingStore(SQLAlchemyOutboxStore):
    def __init__(self, sessions: async_sessionmaker[AsyncSession], *, destination: str) -> None:
        super().__init__(sessions, destination=destination)
        self.claim_transactions = 0
        self.batch_update_transactions = 0
        self.single_update_transactions = 0

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        claimed = await super().claim_batch(
            batch_size=batch_size, lease_seconds=lease_seconds, now=now
        )
        self.claim_transactions += 1
        return claimed

    async def mark_published_batch(
        self, *, claims: tuple[ClaimedOutboxEvent, ...], published_at: datetime
    ) -> tuple[str, ...]:
        self.batch_update_transactions += 1
        return await super().mark_published_batch(
            claims=claims, published_at=published_at
        )

    async def mark_published(
        self, *, outbox_id: str, claim_token: str, published_at: datetime | None = None
    ) -> bool:
        self.single_update_transactions += 1
        return await super().mark_published(
            outbox_id=outbox_id,
            claim_token=claim_token,
            published_at=published_at,
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cost01c_real_twenty_events_two_sqs_calls_two_pg_updates() -> None:
    assert os.environ.get("AWS_ENDPOINT_URL") == "http://127.0.0.1:4566"
    settings = get_settings()
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    redis: Redis = Redis(
        host=os.environ.get("REDIS_HOST", "127.0.0.1"),
        port=int(os.environ.get("REDIS_PORT", "16379")),
        decode_responses=True,
    )
    sqs: BotoSQSClient = boto3.client(
        "sqs",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}),
    )
    destination = "cost01c-" + uuid4().hex
    key = "cost01c-circuit-" + uuid4().hex
    queue_url = sqs.create_queue(QueueName="cost01c-" + uuid4().hex)["QueueUrl"]
    ids = ["cost01c-" + uuid4().hex for _ in range(20)]
    store = CountingStore(sessions, destination=destination)
    counter = CountingBatchClient(sqs)
    queue = SQSEventQueue(cast(TransportClient, counter), queue_url=queue_url)
    try:
        base = datetime.now(UTC) - timedelta(minutes=2)
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)
            for position, event_id in enumerate(ids):
                event = create_event_envelope(
                    event_id=event_id,
                    event_type="vehicle.command.requested",
                    source="cost01c-integration",
                    payload={"vehicle_id": "VIN-COST01C", "command": "lock"},
                )
                repository.add(
                    PendingOutboxEvent.from_event(
                        event,
                        destination=destination,
                        created_at=base + timedelta(microseconds=position),
                        available_at=base,
                    )
                )
            await uow.commit()

        circuit = RedisCircuitBreaker(redis, key=key, policy=CircuitPolicy())
        dispatcher = OutboxDispatcher(
            store=store,
            destinations=MappingOutboxDestinationResolver(
                {destination: queue.send_event}
            ),
            batch_publisher=queue.send_events_batch,
            batch_mark_published=store.mark_published_batch,
            batch_destination=destination,
            retry_policy=RetryPolicy(max_attempts=3),
            batch_size=20,
            lease_seconds=60,
            circuit=circuit,
        )
        result = await dispatcher.dispatch_batch()
        assert result.claimed == result.published == 20
        assert result.retries_scheduled == result.failed == 0
        assert result.stale_claims == result.released_unattempted == 0
        assert store.claim_transactions == 1
        assert store.batch_update_transactions == 2
        assert store.single_update_transactions == 0
        assert counter.batch_calls == 2
        assert counter.single_calls == 0

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
            assert len(rows) == 20
            assert all(row.status == "published" and row.attempts == 1 for row in rows)
            assert all(row.claim_token is None for row in rows)

        received: set[str] = set()
        for _ in range(40):
            if len(received) == len(ids):
                break
            messages = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            ).get("Messages", [])
            for message in messages:
                body = json.loads(message["Body"])
                assert isinstance(body, dict)
                received_id = body.get("event_id")
                assert isinstance(received_id, str)
                received.add(received_id)
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )
        assert received == set(ids)
        print(
            "COST01C_REAL=events:20 claim:1 send_api:2 pg_publish_update:2 "
            "single_send_api:0 single_publish_update:0",
            flush=True,
        )
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
            )
        await redis.delete(key)
        await redis.aclose()
        sqs.delete_queue(QueueUrl=queue_url)
        sqs.close()
        await engine.dispose()
