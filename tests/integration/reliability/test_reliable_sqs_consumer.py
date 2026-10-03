from __future__ import annotations

import asyncio
from hashlib import sha256
from typing import NotRequired, Protocol, TypedDict, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

from enterprise_platform.cache.client import (
    CacheKeyBuilder,
    create_redis_resources,
)
from enterprise_platform.cache.lifecycle import (
    close_redis_resources,
)
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from enterprise_platform.messaging.factory import (
    create_sqs_event_queue,
)
from enterprise_platform.messaging.reliable_sqs_consumer import (
    MessageProcessingResult,
    ReliableSQSEventProcessor,
)
from enterprise_platform.messaging.sqs import (
    ReceivedEventMessage,
    SQSEventQueue,
)
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
    IdempotencyPolicy,
    IdempotencyService,
)
from enterprise_platform.reliability.redis_idempotency import (
    RedisIdempotencyStore,
)


class SQSCreateQueueResponse(TypedDict):
    QueueUrl: NotRequired[str]


class SQSAdminClient(Protocol):
    def create_queue(
        self,
        *,
        QueueName: str,
        Attributes: dict[str, str],
    ) -> SQSCreateQueueResponse: ...

    def delete_queue(
        self,
        *,
        QueueUrl: str,
    ) -> object: ...


def normalize_localstack_queue_url(
    returned_queue_url: str,
    *,
    endpoint_url: str,
) -> str:
    queue_parts = urlsplit(returned_queue_url)
    endpoint_parts = urlsplit(endpoint_url)

    return urlunsplit(
        (
            endpoint_parts.scheme,
            endpoint_parts.netloc,
            queue_parts.path,
            "",
            "",
        )
    )


def build_redis_key(
    key_builder: CacheKeyBuilder,
    event_id: str,
) -> str:
    digest = sha256(event_id.encode("utf-8")).hexdigest()

    return key_builder.build(
        "idempotency",
        digest,
    )


async def receive_one(
    queue: SQSEventQueue,
) -> ReceivedEventMessage:
    for _ in range(20):
        messages = await queue.receive_events(
            max_messages=1,
            wait_time_seconds=0,
        )

        if messages:
            return messages[0]

        await asyncio.sleep(0.1)

    raise AssertionError("Expected SQS message was not received.")


class FailDeleteOnceAcknowledger:
    def __init__(
        self,
        queue: SQSEventQueue,
    ) -> None:
        self._queue = queue
        self._failed = False

    async def delete_message(
        self,
        receipt_handle: str,
    ) -> None:
        if not self._failed:
            self._failed = True

            raise RuntimeError("simulated delete failure")

        await self._queue.delete_message(receipt_handle)


@pytest.mark.asyncio
async def test_real_sqs_and_redis_process_event_once() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK
    assert settings.aws_endpoint_url is not None

    sqs_client = cast(
        SQSAdminClient,
        AWSClientFactory(settings).sqs(),
    )

    queue_name = f"connected-vehicle-reliable-consumer-{uuid4().hex}"

    queue_url: str | None = None
    redis_resources = create_redis_resources(settings)

    key_builder = CacheKeyBuilder(prefix=(f"connected-vehicle:integration:{uuid4().hex}"))

    event = create_event_envelope(
        event_type="vehicle.command.requested",
        source="reliable-consumer-integration",
        payload={
            "vehicle_id": "VIN-RELIABLE-001",
            "command": "unlock",
        },
    )

    redis_key = build_redis_key(
        key_builder,
        event.event_id,
    )

    try:
        response = sqs_client.create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "0",
            },
        )

        returned_queue_url = response.get("QueueUrl")

        assert returned_queue_url

        queue_url = normalize_localstack_queue_url(
            returned_queue_url,
            endpoint_url=settings.aws_endpoint_url,
        )

        queue = create_sqs_event_queue(
            settings,
            queue_url=queue_url,
        )

        store = RedisIdempotencyStore(
            redis_resources.client,
            key_builder=key_builder,
        )

        idempotency = IdempotencyService(
            store,
            policy=IdempotencyPolicy(
                in_progress_ttl_seconds=60,
                completed_ttl_seconds=3600,
            ),
        )

        processor = ReliableSQSEventProcessor(
            acknowledger=queue,
            idempotency=idempotency,
        )

        handled: list[EventEnvelope] = []

        async def handler(
            received_event: EventEnvelope,
        ) -> None:
            handled.append(received_event)

        await queue.send_event(event)

        message = await receive_one(queue)

        result = await processor.process(
            message,
            handler=handler,
        )

        assert result is MessageProcessingResult.PROCESSED

        assert handled == [event]

        assert await idempotency.begin(event.event_id) is IdempotencyDecision.COMPLETED

    finally:
        await redis_resources.client.delete(redis_key)

        await close_redis_resources(redis_resources)

        if queue_url is not None:
            sqs_client.delete_queue(QueueUrl=queue_url)


@pytest.mark.asyncio
async def test_completed_event_is_not_reprocessed_after_ack_failure() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK
    assert settings.aws_endpoint_url is not None

    sqs_client = cast(
        SQSAdminClient,
        AWSClientFactory(settings).sqs(),
    )

    queue_name = f"connected-vehicle-ack-failure-{uuid4().hex}"

    queue_url: str | None = None
    redis_resources = create_redis_resources(settings)

    key_builder = CacheKeyBuilder(prefix=(f"connected-vehicle:integration:{uuid4().hex}"))

    event = create_event_envelope(
        event_type="vehicle.command.requested",
        source="ack-failure-integration",
        payload={
            "vehicle_id": "VIN-RELIABLE-002",
            "command": "lock",
        },
    )

    redis_key = build_redis_key(
        key_builder,
        event.event_id,
    )

    try:
        response = sqs_client.create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "0",
            },
        )

        returned_queue_url = response.get("QueueUrl")

        assert returned_queue_url

        queue_url = normalize_localstack_queue_url(
            returned_queue_url,
            endpoint_url=settings.aws_endpoint_url,
        )

        queue = create_sqs_event_queue(
            settings,
            queue_url=queue_url,
        )

        store = RedisIdempotencyStore(
            redis_resources.client,
            key_builder=key_builder,
        )

        idempotency = IdempotencyService(
            store,
            policy=IdempotencyPolicy(
                in_progress_ttl_seconds=60,
                completed_ttl_seconds=3600,
            ),
        )

        acknowledger = FailDeleteOnceAcknowledger(queue)

        processor = ReliableSQSEventProcessor(
            acknowledger=acknowledger,
            idempotency=idempotency,
        )

        handled: list[EventEnvelope] = []

        async def handler(
            received_event: EventEnvelope,
        ) -> None:
            handled.append(received_event)

        await queue.send_event(event)

        first_message = await receive_one(queue)

        with pytest.raises(
            RuntimeError,
            match="simulated delete failure",
        ):
            await processor.process(
                first_message,
                handler=handler,
            )

        assert handled == [event]

        assert await idempotency.begin(event.event_id) is IdempotencyDecision.COMPLETED

        redelivered_message = await receive_one(queue)

        result = await processor.process(
            redelivered_message,
            handler=handler,
        )

        assert result is MessageProcessingResult.DUPLICATE

        assert handled == [event]

    finally:
        await redis_resources.client.delete(redis_key)

        await close_redis_resources(redis_resources)

        if queue_url is not None:
            sqs_client.delete_queue(QueueUrl=queue_url)
