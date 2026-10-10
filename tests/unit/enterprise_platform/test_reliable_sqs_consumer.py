from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from enterprise_platform.messaging.reliable_sqs_consumer import (
    MessageProcessingResult,
    ReliableSQSEventProcessor,
)
from enterprise_platform.messaging.sqs import (
    ReceivedEventMessage,
)
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
)


@dataclass
class FakeAcknowledger:
    deleted: list[str] = field(default_factory=list)

    async def delete_message(
        self,
        receipt_handle: str,
    ) -> None:
        self.deleted.append(receipt_handle)


@dataclass
class FakeIdempotencyCoordinator:
    decision: IdempotencyDecision
    begun: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    abandoned: list[str] = field(default_factory=list)

    async def begin(
        self,
        key: str,
    ) -> IdempotencyDecision:
        self.begun.append(key)
        return self.decision

    async def complete(
        self,
        key: str,
    ) -> None:
        self.completed.append(key)

    async def abandon(
        self,
        key: str,
    ) -> None:
        self.abandoned.append(key)


def create_message(
    *,
    event_id: str = "event-001",
) -> ReceivedEventMessage:
    event = create_event_envelope(
        event_id=event_id,
        event_type="vehicle.command.requested",
        source="test",
        payload={
            "vehicle_id": "VIN001",
        },
    )

    return ReceivedEventMessage(
        message_id="message-001",
        receipt_handle="receipt-001",
        event=event,
    )


@pytest.mark.asyncio
async def test_processor_handles_and_acknowledges_new_event() -> None:
    acknowledger = FakeAcknowledger()
    idempotency = FakeIdempotencyCoordinator(decision=IdempotencyDecision.ACQUIRED)

    handled: list[EventEnvelope] = []

    async def handler(
        event: EventEnvelope,
    ) -> None:
        handled.append(event)

    processor = ReliableSQSEventProcessor(
        acknowledger=acknowledger,
        idempotency=idempotency,
    )

    message = create_message()

    result = await processor.process(
        message,
        handler=handler,
    )

    assert result is MessageProcessingResult.PROCESSED
    assert handled == [message.event]
    assert idempotency.begun == ["event-001"]
    assert idempotency.completed == ["event-001"]
    assert idempotency.abandoned == []
    assert acknowledger.deleted == ["receipt-001"]


@pytest.mark.asyncio
async def test_processor_acknowledges_completed_duplicate_without_reprocessing() -> None:
    acknowledger = FakeAcknowledger()
    idempotency = FakeIdempotencyCoordinator(decision=IdempotencyDecision.COMPLETED)

    handler_called = False

    async def handler(
        event: EventEnvelope,
    ) -> None:
        nonlocal handler_called
        handler_called = True

    processor = ReliableSQSEventProcessor(
        acknowledger=acknowledger,
        idempotency=idempotency,
    )

    result = await processor.process(
        create_message(),
        handler=handler,
    )

    assert result is MessageProcessingResult.DUPLICATE
    assert handler_called is False
    assert idempotency.completed == []
    assert idempotency.abandoned == []
    assert acknowledger.deleted == ["receipt-001"]


@pytest.mark.asyncio
async def test_processor_does_not_ack_in_progress_event() -> None:
    acknowledger = FakeAcknowledger()
    idempotency = FakeIdempotencyCoordinator(decision=IdempotencyDecision.IN_PROGRESS)

    handler_called = False

    async def handler(
        event: EventEnvelope,
    ) -> None:
        nonlocal handler_called
        handler_called = True

    processor = ReliableSQSEventProcessor(
        acknowledger=acknowledger,
        idempotency=idempotency,
    )

    result = await processor.process(
        create_message(),
        handler=handler,
    )

    assert result is MessageProcessingResult.IN_PROGRESS
    assert handler_called is False
    assert idempotency.completed == []
    assert idempotency.abandoned == []
    assert acknowledger.deleted == []


@pytest.mark.asyncio
async def test_processor_abandons_and_does_not_ack_handler_failure() -> None:
    acknowledger = FakeAcknowledger()
    idempotency = FakeIdempotencyCoordinator(decision=IdempotencyDecision.ACQUIRED)

    async def handler(
        event: EventEnvelope,
    ) -> None:
        raise RuntimeError("processing failed")

    processor = ReliableSQSEventProcessor(
        acknowledger=acknowledger,
        idempotency=idempotency,
    )

    with pytest.raises(
        RuntimeError,
        match="processing failed",
    ):
        await processor.process(
            create_message(),
            handler=handler,
        )

    assert idempotency.completed == []
    assert idempotency.abandoned == ["event-001"]
    assert acknowledger.deleted == []


@pytest.mark.asyncio
async def test_processor_completes_before_acknowledgement() -> None:
    order: list[str] = []

    class OrderedAcknowledger:
        async def delete_message(
            self,
            receipt_handle: str,
        ) -> None:
            order.append("delete")

    class OrderedIdempotency:
        async def begin(
            self,
            key: str,
        ) -> IdempotencyDecision:
            order.append("begin")
            return IdempotencyDecision.ACQUIRED

        async def complete(
            self,
            key: str,
        ) -> None:
            order.append("complete")

        async def abandon(
            self,
            key: str,
        ) -> None:
            order.append("abandon")

    async def handler(
        event: EventEnvelope,
    ) -> None:
        order.append("handler")

    processor = ReliableSQSEventProcessor(
        acknowledger=OrderedAcknowledger(),
        idempotency=OrderedIdempotency(),
    )

    await processor.process(
        create_message(),
        handler=handler,
    )

    assert order == [
        "begin",
        "handler",
        "complete",
        "delete",
    ]


async def test_cancelled_handler_abandons_claim_and_never_acknowledges() -> None:
    acknowledger = FakeAcknowledger()
    idempotency = FakeIdempotencyCoordinator(decision=IdempotencyDecision.ACQUIRED)
    processor = ReliableSQSEventProcessor(acknowledger=acknowledger, idempotency=idempotency)
    message = create_message()

    async def handler(event: EventEnvelope) -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await processor.process(message, handler=handler)
    assert idempotency.abandoned == [message.event.event_id]
    assert idempotency.completed == []
    assert acknowledger.deleted == []
