from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Protocol

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.sqs import ReceivedEventMessage
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
)

EventHandler = Callable[
    [EventEnvelope],
    Awaitable[None],
]


class SQSMessageAcknowledger(Protocol):
    async def delete_message(
        self,
        receipt_handle: str,
    ) -> None: ...


class IdempotencyCoordinator(Protocol):
    async def begin(
        self,
        key: str,
    ) -> IdempotencyDecision: ...

    async def complete(
        self,
        key: str,
    ) -> None: ...

    async def abandon(
        self,
        key: str,
    ) -> None: ...


class MessageProcessingResult(StrEnum):
    PROCESSED = "processed"
    DUPLICATE = "duplicate"
    IN_PROGRESS = "in_progress"


class ReliableSQSEventProcessor:
    """Coordinates SQS acknowledgement and idempotent event processing."""

    def __init__(
        self,
        *,
        acknowledger: SQSMessageAcknowledger,
        idempotency: IdempotencyCoordinator,
    ) -> None:
        self._acknowledger = acknowledger
        self._idempotency = idempotency

    async def process(
        self,
        message: ReceivedEventMessage,
        *,
        handler: EventHandler,
    ) -> MessageProcessingResult:
        idempotency_key = message.event.event_id

        decision = await self._idempotency.begin(idempotency_key)

        if decision is IdempotencyDecision.COMPLETED:
            await self._acknowledger.delete_message(message.receipt_handle)

            return MessageProcessingResult.DUPLICATE

        if decision is IdempotencyDecision.IN_PROGRESS:
            return MessageProcessingResult.IN_PROGRESS

        try:
            await handler(message.event)
        except Exception as handler_error:
            try:
                await self._idempotency.abandon(idempotency_key)
            except Exception as cleanup_error:
                raise cleanup_error from handler_error

            raise

        await self._idempotency.complete(idempotency_key)

        await self._acknowledger.delete_message(message.receipt_handle)

        return MessageProcessingResult.PROCESSED
