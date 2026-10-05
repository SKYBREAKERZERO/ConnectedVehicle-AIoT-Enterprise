from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from enterprise_platform.messaging.envelope import (
    EventEnvelope,
)
from enterprise_platform.messaging.reliable_sqs_consumer import (
    MessageProcessingResult,
    ReliableSQSEventProcessor,
)
from enterprise_platform.messaging.sqs import (
    ReceivedEventMessage,
)


class RemoteCommandSQSQueue(Protocol):
    async def receive_events(
        self,
        *,
        max_messages: int = 10,
        wait_time_seconds: int = 0,
    ) -> tuple[ReceivedEventMessage, ...]: ...


RemoteCommandEventHandler = Callable[
    [EventEnvelope],
    Awaitable[None],
]


@dataclass(frozen=True, slots=True)
class RemoteCommandWorkerBatchResult:
    received: int
    processed: int
    duplicates: int
    in_progress: int
    failed: int


class RemoteCommandSQSWorker:
    """Poll and process one batch of remote-command SQS messages."""

    def __init__(
        self,
        *,
        queue: RemoteCommandSQSQueue,
        processor: ReliableSQSEventProcessor,
        handler: RemoteCommandEventHandler,
        batch_size: int = 10,
        wait_time_seconds: int = 20,
    ) -> None:
        if not 1 <= batch_size <= 10:
            raise ValueError("Remote command worker batch_size must be between 1 and 10.")

        if not 0 <= wait_time_seconds <= 20:
            raise ValueError("Remote command worker wait_time_seconds must be between 0 and 20.")

        self._queue = queue
        self._processor = processor
        self._handler = handler
        self._batch_size = batch_size
        self._wait_time_seconds = wait_time_seconds

    async def run_once(
        self,
    ) -> RemoteCommandWorkerBatchResult:
        messages = await self._queue.receive_events(
            max_messages=self._batch_size,
            wait_time_seconds=self._wait_time_seconds,
        )

        processed = 0
        duplicates = 0
        in_progress = 0
        failed = 0

        for message in messages:
            try:
                result = await self._processor.process(
                    message,
                    handler=self._handler,
                )
            except Exception:
                failed += 1
                continue

            if result is MessageProcessingResult.PROCESSED:
                processed += 1
            elif result is MessageProcessingResult.DUPLICATE:
                duplicates += 1
            elif result is MessageProcessingResult.IN_PROGRESS:
                in_progress += 1
            else:
                raise RuntimeError(f"Unknown SQS processing result: {result!r}.")

        return RemoteCommandWorkerBatchResult(
            received=len(messages),
            processed=processed,
            duplicates=duplicates,
            in_progress=in_progress,
            failed=failed,
        )
