"""Cost-01B: real PG17/Redis/LocalStack SQS batch efficiency benchmark.

The measured region includes claim, publish and Outbox state commits.
Seeding, verification and cleanup are excluded. Results are not AWS prices.
"""

from __future__ import annotations

import json
import math
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import mean
from typing import cast
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from mypy_boto3_sqs.client import SQSClient
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
from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.sqs import SQSClient as TransportSQSClient
from enterprise_platform.messaging.sqs import SQSEventQueue
from enterprise_platform.reliability.circuit_breaker import CircuitPolicy, RedisCircuitBreaker
from enterprise_platform.reliability.outbox import ClaimedOutboxEvent, PendingOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


class MeasuredStore(SQLAlchemyOutboxStore):
    def __init__(
        self, sessions: async_sessionmaker[AsyncSession], *, destination: str
    ) -> None:
        super().__init__(sessions, destination=destination)
        self.claim_transactions = 0
        self.published_transactions = 0

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        result = await super().claim_batch(
            batch_size=batch_size, lease_seconds=lease_seconds, now=now
        )
        self.claim_transactions += 1
        return result

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
    ) -> bool:
        result = await super().mark_published(
            outbox_id=outbox_id, claim_token=claim_token, published_at=published_at
        )
        self.published_transactions += 1
        return result


class MeasuredCircuit(RedisCircuitBreaker):
    def __init__(self, client: Redis, *, key: str) -> None:
        super().__init__(client, key=key, policy=CircuitPolicy())
        self.redis_eval_calls = 0

    async def _act(self, action: str, token: str = "") -> str:
        self.redis_eval_calls += 1
        return await super()._act(action, token)


def percentile_95(values: list[float]) -> float:
    assert values
    ordered = sorted(values)
    return round(ordered[math.ceil(0.95 * len(ordered)) - 1], 3)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cost01b_real_batch_matrix() -> None:
    """Benchmark actual dispatches; enforce accounting, never speed thresholds."""
    report_file = os.environ.get("OUTBOX_COST_REPORT")
    assert report_file, "OUTBOX_COST_REPORT must bind the evidence output"
    event_count = int(os.environ.get("OUTBOX_COST_EVENTS", "200"))
    assert 100 <= event_count <= 1000
    assert os.getenv("CLOUD_RUNTIME") == "localstack"
    assert os.environ["AWS_ENDPOINT_URL"] == "http://127.0.0.1:4566"

    settings = get_settings()
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    cache: Redis = Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "16379")),
        decode_responses=True,
    )
    client: SQSClient = boto3.client(
        "sqs",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 1}),
    )
    batches = (1, 5, 10, 20)
    measurements: list[dict[str, float | int]] = []
    try:
        assert await cache.ping()
        client.list_queues()
        for batch_size in batches:
            destination = "cost01b-" + uuid4().hex
            key = "cost01b-circuit:" + uuid4().hex
            queue_url = client.create_queue(QueueName="cost01b-" + uuid4().hex)["QueueUrl"]
            queue = SQSEventQueue(cast(TransportSQSClient, client), queue_url=queue_url)
            store = MeasuredStore(sessions, destination=destination)
            circuit = MeasuredCircuit(cache, key=key)
            ids = ["cost01b-" + uuid4().hex for _ in range(event_count)]
            message_latencies_ms: list[float] = []
            sqs_sends = 0
            received: set[str] = set()
            try:
                base_time = datetime.now(UTC) - timedelta(minutes=2)
                async with SQLAlchemyUnitOfWork(sessions) as uow:
                    repo = SQLAlchemyOutboxRepository(uow.session)
                    for sequence, event_id in enumerate(ids):
                        event = create_event_envelope(
                            event_id=event_id,
                            event_type="vehicle.command.requested",
                            source="cost01b-benchmark",
                            payload={"vehicle_id": "VIN-COST01B", "command": "lock"},
                        )
                        repo.add(
                            PendingOutboxEvent.from_event(
                                event,
                                destination=destination,
                                created_at=base_time + timedelta(microseconds=sequence),
                                available_at=base_time,
                            )
                        )
                    await uow.commit()

                async def publisher(event: EventEnvelope) -> str:
                    nonlocal sqs_sends
                    start = time.perf_counter_ns()
                    message_id = await queue.send_event(event)
                    message_latencies_ms.append(
                        (time.perf_counter_ns() - start) / 1_000_000
                    )
                    sqs_sends += 1
                    return message_id

                dispatcher = OutboxDispatcher(
                    store=store,
                    destinations=MappingOutboxDestinationResolver(
                        {destination: publisher}
                    ),
                    retry_policy=RetryPolicy(max_attempts=3),
                    batch_size=batch_size,
                    lease_seconds=60,
                    circuit=circuit,
                )
                published = 0
                cpu_start = time.process_time_ns()
                wall_start = time.perf_counter_ns()
                while published < event_count:
                    outcome = await dispatcher.dispatch_batch()
                    assert outcome.claimed > 0
                    assert outcome.published == outcome.claimed
                    assert outcome.retries_scheduled == 0
                    assert outcome.failed == 0
                    assert outcome.stale_claims == 0
                    assert outcome.released_unattempted == 0
                    published += outcome.published
                    assert (time.perf_counter_ns() - wall_start) < 120_000_000_000
                elapsed_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
                process_cpu_ms = (time.process_time_ns() - cpu_start) / 1_000_000

                assert published == event_count
                assert sqs_sends == event_count
                assert store.claim_transactions == math.ceil(event_count / batch_size)
                assert store.published_transactions == event_count
                assert circuit.redis_eval_calls == (
                    store.claim_transactions + event_count
                )

                async with sessions() as session:
                    rows = (
                        (
                            await session.execute(
                                select(OutboxEventModel).where(
                                    OutboxEventModel.event_id.in_(ids)
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                assert len(rows) == event_count
                assert all(
                    row.status == "published" and row.attempts == 1
                    for row in rows
                )

                for _ in range(event_count // 5 + 20):
                    if len(received) >= event_count:
                        break
                    response = client.receive_message(
                        QueueUrl=queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=1,
                    )
                    for message in response.get("Messages", []):
                        parsed = json.loads(message["Body"])
                        assert isinstance(parsed, dict)
                        event_id = parsed.get("event_id")
                        assert isinstance(event_id, str)
                        received.add(event_id)
                        client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=message["ReceiptHandle"],
                        )
                assert received == set(ids), "SQS received event IDs differ"

                measurements.append(
                    {
                        "batch_size": batch_size,
                        "event_count": event_count,
                        "published": published,
                        "claim_transactions": store.claim_transactions,
                        "published_transactions": store.published_transactions,
                        "redis_eval_calls": circuit.redis_eval_calls,
                        "sqs_send_calls": sqs_sends,
                        "sqs_unique_received": len(received),
                        "elapsed_ms": round(elapsed_ms, 3),
                        "process_cpu_ms": round(process_cpu_ms, 3),
                        "throughput_events_per_sec": round(
                            event_count * 1000 / elapsed_ms, 3
                        ),
                        "sqs_send_mean_ms": round(mean(message_latencies_ms), 3),
                        "sqs_send_p95_ms": percentile_95(message_latencies_ms),
                    }
                )
            finally:
                async with engine.begin() as connection:
                    await connection.execute(
                        delete(OutboxEventModel).where(
                            OutboxEventModel.event_id.in_(ids)
                        )
                    )
                await cache.delete(key)
                client.delete_queue(QueueUrl=queue_url)

        report = {
            "schema": "outbox-cost-benchmark-v1",
            "environment": "github-hosted-postgres17-redis-localstack",
            "method": "single-worker-sequential-real-sqs",
            "event_count_per_batch": event_count,
            "runs": measurements,
            "notes": (
                "CPU is Python process time only; wall time includes real PostgreSQL "
                "commits, Redis Lua and LocalStack SQS SendMessage. Seed/verify/cleanup "
                "are excluded. This is not AWS billing or a concurrency SLO."
            ),
        }
        output = Path(report_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("COST01B_BENCHMARK=" + json.dumps(report, sort_keys=True), flush=True)
    finally:
        client.close()
        await cache.aclose()
        await engine.dispose()
