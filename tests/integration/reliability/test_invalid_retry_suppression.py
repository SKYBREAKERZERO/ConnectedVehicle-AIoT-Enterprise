"""Enterprise invalid-retry gate: real PG17, Redis and LocalStack SQS faults.

Network faults are injected at the SQS adapter boundary. LocalStack accepts the
successful subset (or all entries before a simulated lost response); PostgreSQL
persists the resulting outcome. The queue is never substituted by an in-memory
message sink.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import EndpointConnectionError
from mypy_boto3_sqs.client import SQSClient as BotoSQSClient
from redis.asyncio import Redis
from sqlalchemy import delete, select

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
    SQSClient,
    SQSEventQueue,
)
from enterprise_platform.reliability.circuit_breaker import CircuitPolicy, RedisCircuitBreaker
from enterprise_platform.reliability.outbox import PendingOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


class InjectedSQSClient:
    """Forward accepted messages to real LocalStack; inject only the SQS response."""

    def __init__(self, underlying: BotoSQSClient, *, mode: Literal["partial", "lost"]) -> None:
        self.underlying = underlying
        self.mode = mode
        self.calls = 0

    def send_message_batch(
        self, *, QueueUrl: str, Entries: list[dict[str, str]]
    ) -> SQSBatchSendResponse:
        self.calls += 1
        assert len(Entries) == 4
        if self.mode == "lost":
            cast(Any, self.underlying).send_message_batch(QueueUrl=QueueUrl, Entries=Entries)
            # SQS accepted the batch but the client never obtained the response.
            raise EndpointConnectionError(endpoint_url="http://127.0.0.1:4566")
        accepted = [entry for entry in Entries if entry["Id"] not in {"1", "2"}]
        result = cast(
            SQSBatchSendResponse,
            cast(Any, self.underlying).send_message_batch(
                QueueUrl=QueueUrl, Entries=accepted
            ),
        )
        return {
            "Successful": result["Successful"],
            "Failed": [
                {"Id": "1", "Code": "Throttling", "SenderFault": False},
                {"Id": "2", "Code": "InvalidMessageContents", "SenderFault": True},
            ],
        }

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, str]:
        raise AssertionError("CLOSED batch must not fall back to individual sends")


async def exercise_fault(mode: Literal["partial", "lost"]) -> None:
    assert os.environ.get("CLOUD_RUNTIME") == "localstack"
    assert os.environ.get("AWS_ENDPOINT_URL") == "http://127.0.0.1:4566"
    settings = get_settings()
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    cache: Redis = Redis(
        host=os.environ.get("REDIS_HOST", "127.0.0.1"),
        port=int(os.environ.get("REDIS_PORT", "16379")),
        decode_responses=True,
    )
    sqs: BotoSQSClient = boto3.client(
        "sqs",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name="us-east-1",
        config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}),
    )
    prefix = "retry-e2e-" + uuid4().hex
    destination = prefix
    redis_key = prefix + "-circuit"
    ids = [prefix + "-" + str(index) for index in range(4)]
    queue_url = sqs.create_queue(QueueName=prefix)["QueueUrl"]
    injected = InjectedSQSClient(sqs, mode=mode)
    queue = SQSEventQueue(cast(SQSClient, injected), queue_url=queue_url)
    try:
        base = datetime.now(UTC) - timedelta(minutes=1)
        async with SQLAlchemyUnitOfWork(sessions) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)
            for index, event_id in enumerate(ids):
                event = create_event_envelope(
                    event_id=event_id,
                    event_type="vehicle.command.requested",
                    source="retry-suppression-real-integration",
                    payload={"vehicle_id": "VIN-RETRY-SUPPRESSION", "command": "lock"},
                )
                repository.add(
                    PendingOutboxEvent.from_event(
                        event,
                        destination=destination,
                        created_at=base + timedelta(microseconds=index),
                        available_at=base,
                    )
                )
            await uow.commit()

        store = SQLAlchemyOutboxStore(sessions, destination=destination)
        circuit = RedisCircuitBreaker(
            cache, key=redis_key, policy=CircuitPolicy(failure_threshold=5)
        )
        dispatcher = OutboxDispatcher(
            store=store,
            destinations=MappingOutboxDestinationResolver({destination: queue.send_event}),
            retry_policy=RetryPolicy(
                max_attempts=3,
                base_delay_seconds=10,
                max_delay_seconds=10,
                jitter_ratio=0,
            ),
            batch_size=4,
            lease_seconds=60,
            circuit=circuit,
            batch_publisher=queue.send_events_batch,
            batch_mark_published=store.mark_published_batch,
            batch_destination=destination,
        )
        first = await dispatcher.dispatch_batch()
        assert first.claimed == 4 and injected.calls == 1
        assert first.stale_claims == first.released_unattempted == 0
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
            assert len(rows) == 4
            by_id = {row.event_id: row for row in rows}
            assert all(row.attempts == 1 for row in rows)
            assert all(row.claim_token is None for row in rows)
            if mode == "partial":
                assert (first.published, first.retries_scheduled, first.failed) == (2, 1, 1)
                assert [by_id[eid].status for eid in ids] == [
                    "published",
                    "pending",
                    "failed",
                    "published",
                ]
                assert by_id[ids[2]].failure_code == "non_retryable"
                assert by_id[ids[1]].available_at > datetime.now(UTC)
                expected_received = {ids[0], ids[3]}
            else:
                assert (first.published, first.retries_scheduled, first.failed) == (0, 4, 0)
                assert all(row.status == "pending" for row in rows)
                assert all(row.available_at > datetime.now(UTC) for row in rows)
                expected_received = set(ids)

        # Future retry is persisted, not a hot loop issuing extra SQS requests.
        assert (await dispatcher.dispatch_batch()).claimed == 0
        assert injected.calls == 1

        received: set[str] = set()
        for _ in range(4):
            messages = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            ).get("Messages", [])
            for message in messages:
                body = json.loads(message["Body"])
                assert isinstance(body, dict)
                event_id = body.get("event_id")
                assert isinstance(event_id, str)
                received.add(event_id)
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )
            if received == expected_received:
                break
        assert received == expected_received
        print(
            f"INVALID_RETRY_REAL={mode}: attempted_api:1 "
            f"published:{first.published} retry:{first.retries_scheduled} "
            f"failed:{first.failed} idle_api:0",
            flush=True,
        )
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id.in_(ids))
            )
        await cache.delete(redis_key)
        await cache.aclose()
        sqs.delete_queue(QueueUrl=queue_url)
        sqs.close()
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_retry_sender_fault_is_terminal_but_throttle_is_delayed() -> None:
    await exercise_fault("partial")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_retry_lost_response_does_not_ack_or_hot_loop() -> None:
    await exercise_fault("lost")
