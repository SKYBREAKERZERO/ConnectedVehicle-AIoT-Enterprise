from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from connected_vehicle.remote_command.sqs_worker import (
    RemoteCommandSQSWorker,
)
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from enterprise_platform.messaging.reliable_sqs_consumer import (
    MessageProcessingResult,
)
from enterprise_platform.messaging.sqs import (
    ReceivedEventMessage,
)


def create_message(
    index: int,
) -> ReceivedEventMessage:
    event = create_event_envelope(
        event_id=f"event-{index}",
        event_type="vehicle.command.requested",
        source="worker-test",
        payload={
            "index": index,
        },
    )

    return ReceivedEventMessage(
        message_id=f"message-{index}",
        receipt_handle=f"receipt-{index}",
        event=event,
    )


@dataclass
class FakeQueue:
    messages: tuple[ReceivedEventMessage, ...]

    calls: list[tuple[int, int]] = field(default_factory=list)

    async def receive_events(
        self,
        *,
        max_messages: int = 10,
        wait_time_seconds: int = 0,
    ) -> tuple[ReceivedEventMessage, ...]:
        self.calls.append(
            (
                max_messages,
                wait_time_seconds,
            )
        )

        return self.messages


class FakeProcessor:
    def __init__(
        self,
        results: dict[
            str,
            MessageProcessingResult | Exception,
        ],
    ) -> None:
        self._results = results
        self.processed: list[str] = []

    async def process(
        self,
        message: ReceivedEventMessage,
        *,
        handler: object,
    ) -> MessageProcessingResult:
        del handler

        self.processed.append(message.message_id)

        result = self._results[message.message_id]

        if isinstance(result, Exception):
            raise result

        return result


async def noop_handler(
    event: EventEnvelope,
) -> None:
    del event


@pytest.mark.asyncio
async def test_worker_processes_empty_batch() -> None:
    queue = FakeQueue(messages=())

    processor = FakeProcessor({})

    worker = RemoteCommandSQSWorker(
        queue=queue,
        processor=processor,  # type: ignore[arg-type]
        handler=noop_handler,
        batch_size=5,
        wait_time_seconds=3,
    )

    result = await worker.run_once()

    assert result.received == 0
    assert result.processed == 0
    assert result.duplicates == 0
    assert result.in_progress == 0
    assert result.failed == 0

    assert queue.calls == [
        (
            5,
            3,
        )
    ]


@pytest.mark.asyncio
async def test_worker_counts_processing_outcomes() -> None:
    messages = tuple(create_message(index) for index in range(1, 5))

    queue = FakeQueue(messages=messages)

    processor = FakeProcessor(
        {
            "message-1": (MessageProcessingResult.PROCESSED),
            "message-2": (MessageProcessingResult.DUPLICATE),
            "message-3": (MessageProcessingResult.IN_PROGRESS),
            "message-4": (RuntimeError("processing failed")),
        }
    )

    worker = RemoteCommandSQSWorker(
        queue=queue,
        processor=processor,  # type: ignore[arg-type]
        handler=noop_handler,
    )

    result = await worker.run_once()

    assert result.received == 4
    assert result.processed == 1
    assert result.duplicates == 1
    assert result.in_progress == 1
    assert result.failed == 1


@pytest.mark.asyncio
async def test_failed_message_does_not_block_remaining_messages() -> None:
    messages = (
        create_message(1),
        create_message(2),
        create_message(3),
    )

    queue = FakeQueue(messages=messages)

    processor = FakeProcessor(
        {
            "message-1": (RuntimeError("first failed")),
            "message-2": (MessageProcessingResult.PROCESSED),
            "message-3": (MessageProcessingResult.PROCESSED),
        }
    )

    worker = RemoteCommandSQSWorker(
        queue=queue,
        processor=processor,  # type: ignore[arg-type]
        handler=noop_handler,
    )

    result = await worker.run_once()

    assert result.received == 3
    assert result.failed == 1
    assert result.processed == 2

    assert processor.processed == [
        "message-1",
        "message-2",
        "message-3",
    ]


@pytest.mark.parametrize(
    ("batch_size", "wait_time_seconds"),
    [
        (
            0,
            20,
        ),
        (
            11,
            20,
        ),
        (
            10,
            -1,
        ),
        (
            10,
            21,
        ),
    ],
)
def test_worker_rejects_invalid_poll_configuration(
    batch_size: int,
    wait_time_seconds: int,
) -> None:
    with pytest.raises(ValueError):
        RemoteCommandSQSWorker(
            queue=FakeQueue(messages=()),
            processor=FakeProcessor({}),  # type: ignore[arg-type]
            handler=noop_handler,
            batch_size=batch_size,
            wait_time_seconds=wait_time_seconds,
        )
