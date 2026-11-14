"""Actual LocalStack SQS traffic and Redis-shared circuit fault boundaries."""

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from mypy_boto3_sqs.client import SQSClient
from redis.asyncio import Redis

from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.serialization import serialize_event_envelope
from enterprise_platform.reliability.circuit_breaker import (
    CircuitPolicy,
    RedisCircuitBreaker,
)
from enterprise_platform.reliability.outbox import ClaimedOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


@dataclass
class RecordingStore:
    event: ClaimedOutboxEvent
    claims: int = 0
    published: bool = False
    retry_count: int = 0
    next_attempt: datetime | None = None

    async def claim_batch(
        self, *, batch_size: int = 100, lease_seconds: int = 30, now: datetime | None = None
    ) -> tuple[ClaimedOutboxEvent, ...]:
        self.claims += 1
        if self.published:
            return ()
        return (replace(self.event, attempts=self.claims, claim_token=uuid4().hex),)

    async def mark_published(
        self, *, outbox_id: str, claim_token: str, published_at: datetime | None = None
    ) -> bool:
        self.published = True
        return True

    async def schedule_retry(
        self, *, outbox_id: str, claim_token: str, available_at: datetime
    ) -> bool:
        self.retry_count += 1
        self.next_attempt = available_at
        return True

    async def mark_failed(
        self, *, outbox_id: str, claim_token: str, failed_at: datetime, failure_code: str
    ) -> bool:
        return True


def new_event(destination: str = "command") -> RecordingStore:
    event = create_event_envelope(
        event_type="vehicle.command.requested",
        source="outbox-circuit-localstack",
        payload={"vehicle_id": "VIN-CB-001", "command": "lock"},
    )
    now = datetime.now(UTC)
    return RecordingStore(
        ClaimedOutboxEvent(
            id=str(uuid4()),
            event_id=event.event_id,
            event_type=event.event_type,
            destination=destination,
            event_body=serialize_event_envelope(event),
            attempts=0,
            claim_token=uuid4().hex,
            lease_expires_at=now + timedelta(minutes=10),
        )
    )


def redis_client() -> Redis:
    return Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "16379")),
        decode_responses=True,
    )


def sqs_client() -> SQSClient:
    return boto3.client(
        "sqs",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}),
    )


def make_dispatcher(
    store: RecordingStore,
    circuit: RedisCircuitBreaker,
    publisher: Callable[[EventEnvelope], Awaitable[object]],
) -> OutboxDispatcher:
    return OutboxDispatcher(
        store=store,
        destinations=MappingOutboxDestinationResolver({store.event.destination: publisher}),
        retry_policy=RetryPolicy(max_attempts=10),
        circuit=circuit,
    )


@pytest.mark.integration
async def test_cb001_sqs_failures_open_breaker() -> None:
    cache = redis_client()
    key = "cb-localstack:" + uuid4().hex
    breaker = RedisCircuitBreaker(cache, key=key, policy=CircuitPolicy(failure_threshold=2))
    store = new_event()
    bad_sqs = boto3.client(
        "sqs",
        endpoint_url="http://127.0.0.1:1",
        region_name="us-east-1",
        config=Config(connect_timeout=1, read_timeout=1, retries={"max_attempts": 1}),
    )
    attempts = 0

    async def down(_event: EventEnvelope) -> None:
        nonlocal attempts
        attempts += 1
        try:
            bad_sqs.list_queues()
        except Exception as exc:
            raise MessagePublishError() from exc
        raise AssertionError("Fault endpoint unexpectedly accepted SQS request")

    try:
        dispatcher = make_dispatcher(store, breaker, down)
        await dispatcher.dispatch_batch()
        await dispatcher.dispatch_batch()
        assert attempts == 2
        assert store.retry_count == 2
        assert not (await breaker.acquire()).allowed
        await dispatcher.dispatch_batch()
        assert attempts == 2
        assert store.claims == 2
    finally:
        await cache.delete(key)
        await cache.aclose()


@pytest.mark.integration
async def test_cb002_open_blocks_sends_without_claiming() -> None:
    cache = redis_client()
    key = "cb-block:" + uuid4().hex
    breaker = RedisCircuitBreaker(cache, key=key, policy=CircuitPolicy(failure_threshold=1))
    store = new_event()
    sends = 0

    async def publisher(_event: EventEnvelope) -> None:
        nonlocal sends
        sends += 1

    try:
        await breaker.failure(await breaker.acquire())
        result = await make_dispatcher(store, breaker, publisher).dispatch_batch()
        assert result.claimed == 0
        assert store.claims == 0 and sends == 0
    finally:
        await cache.delete(key)
        await cache.aclose()


@pytest.mark.integration
async def test_cb004_sqs_recovery_closes_after_probes() -> None:
    cache = redis_client()
    key = "cb-recovery:" + uuid4().hex
    breaker = RedisCircuitBreaker(
        cache,
        key=key,
        policy=CircuitPolicy(failure_threshold=1, open_seconds=1, successes_to_close=2),
    )
    client = sqs_client()
    queue = client.create_queue(QueueName="cb-recovery-" + uuid4().hex)["QueueUrl"]
    store = new_event()

    async def publisher(event: EventEnvelope) -> None:
        client.send_message(QueueUrl=queue, MessageBody=event.event_id)

    try:
        await breaker.failure(await breaker.acquire())
        assert not (await breaker.acquire()).allowed
        await asyncio.sleep(1.1)
        dispatcher = make_dispatcher(store, breaker, publisher)
        assert (await dispatcher.dispatch_batch()).published == 1
        store.published = False
        assert (await dispatcher.dispatch_batch()).published == 1
        permit = await breaker.acquire()
        assert permit.allowed and not permit.token
        received = client.receive_message(
            QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        assert len(received) == 2
    finally:
        client.delete_queue(QueueUrl=queue)
        await cache.delete(key)
        await cache.aclose()


@pytest.mark.integration
async def test_cb005_finops_open_does_not_block_ota() -> None:
    cache = redis_client()
    prefix = "cb-business:" + uuid4().hex
    policy = CircuitPolicy(failure_threshold=1)
    finops = RedisCircuitBreaker(cache, key=prefix + ":finops", policy=policy)
    ota = RedisCircuitBreaker(cache, key=prefix + ":ota", policy=policy)
    client = sqs_client()
    queue = client.create_queue(QueueName="cb-ota-" + uuid4().hex)["QueueUrl"]
    ota_store = new_event("ota")
    sent = 0

    async def publish_ota(event: EventEnvelope) -> None:
        nonlocal sent
        client.send_message(QueueUrl=queue, MessageBody=event.event_id)
        sent += 1

    try:
        await finops.failure(await finops.acquire())
        assert not (await finops.acquire()).allowed
        assert (await make_dispatcher(ota_store, ota, publish_ota).dispatch_batch()).published == 1
        assert sent == 1
        assert client.receive_message(QueueUrl=queue, MaxNumberOfMessages=1, WaitTimeSeconds=1).get(
            "Messages"
        )
    finally:
        client.delete_queue(QueueUrl=queue)
        await cache.delete(prefix + ":finops", prefix + ":ota")
        await cache.aclose()


@pytest.mark.integration
async def test_cb007_backlog_recovery_respects_rate_limit() -> None:
    cache = redis_client()
    key = "cb-rate:" + uuid4().hex
    breaker = RedisCircuitBreaker(
        cache,
        key=key,
        policy=CircuitPolicy(
            failure_threshold=1,
            open_seconds=1,
            successes_to_close=1,
            min_interval_ms=1000,
        ),
    )
    try:
        first = await breaker.acquire()
        await breaker.failure(first)
        await asyncio.sleep(1.1)
        permits = await asyncio.gather(*(breaker.acquire() for _ in range(30)))
        assert sum(p.allowed for p in permits) == 1
        accepted = next(p for p in permits if p.allowed)
        await breaker.success(accepted)
        assert not (await breaker.acquire()).allowed
    finally:
        await cache.delete(key)
        await cache.aclose()


@pytest.mark.integration
async def test_cb010_unknown_delivery_outcome_reconciled() -> None:
    cache = redis_client()
    key = "cb-unknown:" + uuid4().hex
    breaker = RedisCircuitBreaker(cache, key=key, policy=CircuitPolicy(failure_threshold=5))
    client = sqs_client()
    queue = client.create_queue(QueueName="cb-unknown-" + uuid4().hex)["QueueUrl"]
    store = new_event()
    sends = 0

    async def lost_response(event: EventEnvelope) -> None:
        nonlocal sends
        sends += 1
        client.send_message(QueueUrl=queue, MessageBody=event.event_id)
        if sends == 1:
            # Inject response loss AFTER the external side effect commits.
            raise MessagePublishError()

    try:
        dispatcher = make_dispatcher(store, breaker, lost_response)
        first = await dispatcher.dispatch_batch()
        assert first.retries_scheduled == 1
        assert (await dispatcher.dispatch_batch()).published == 1
        messages = client.receive_message(
            QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        assert len(messages) == 2
        # At-least-once transport: the consumer idempotency ledger fences
        # duplicate business effects by stable event_id.
        ledger: set[str] = set()
        applied = 0
        for message in messages:
            event_id = message["Body"]
            if event_id not in ledger:
                ledger.add(event_id)
                applied += 1
        assert applied == 1
        assert len(ledger) == 1
    finally:
        client.delete_queue(QueueUrl=queue)
        await cache.delete(key)
        await cache.aclose()
