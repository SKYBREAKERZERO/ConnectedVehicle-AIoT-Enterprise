from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, NotRequired, Protocol, TypedDict, cast

from botocore.exceptions import BotoCoreError, ClientError

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.exceptions import (
    InvalidMessageError,
    MessageDeleteError,
    MessagePublishError,
    MessageReceiveError,
)
from enterprise_platform.messaging.serialization import (
    EventSerializationError,
    deserialize_event_envelope,
    serialize_event_envelope,
)


class SQSSendResponse(TypedDict):
    MessageId: NotRequired[str]


class SQSBatchSuccessfulEntry(TypedDict):
    Id: str
    MessageId: str


class SQSBatchFailedEntry(TypedDict):
    Id: str
    Code: str
    SenderFault: bool


class SQSBatchSendResponse(TypedDict):
    Successful: NotRequired[list[SQSBatchSuccessfulEntry]]
    Failed: NotRequired[list[SQSBatchFailedEntry]]


class SQSBatchClient(Protocol):
    def send_message_batch(
        self, *, QueueUrl: str, Entries: list[dict[str, str]]
    ) -> SQSBatchSendResponse: ...


@dataclass(frozen=True, slots=True)
class SQSBatchSendResult:
    event_id: str
    status: Literal["sent", "retryable", "permanent"]
    failure_code: str | None = None


class SQSMessage(TypedDict):
    MessageId: NotRequired[str]
    ReceiptHandle: NotRequired[str]
    Body: NotRequired[str]


class SQSReceiveResponse(TypedDict):
    Messages: NotRequired[list[SQSMessage]]


class SQSClient(Protocol):
    def send_message(
        self,
        *,
        QueueUrl: str,
        MessageBody: str,
    ) -> SQSSendResponse: ...

    def receive_message(
        self,
        *,
        QueueUrl: str,
        MaxNumberOfMessages: int,
        WaitTimeSeconds: int,
    ) -> SQSReceiveResponse: ...

    def delete_message(
        self,
        *,
        QueueUrl: str,
        ReceiptHandle: str,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ReceivedEventMessage:
    message_id: str
    receipt_handle: str
    event: EventEnvelope


def normalize_queue_url(queue_url: str) -> str:
    normalized = queue_url.strip()

    if not normalized:
        raise ValueError("SQS queue URL must not be empty.")

    return normalized


class SQSEventQueue:
    """SQS adapter for platform EventEnvelope messages."""

    def __init__(
        self,
        client: SQSClient,
        *,
        queue_url: str,
    ) -> None:
        self._client = client
        self._queue_url = normalize_queue_url(queue_url)

    @property
    def queue_url(self) -> str:
        return self._queue_url

    async def send_event(
        self,
        event: EventEnvelope,
    ) -> str:
        body = serialize_event_envelope(event)

        try:
            response = await asyncio.to_thread(
                self._client.send_message,
                QueueUrl=self._queue_url,
                MessageBody=body,
            )
        except (BotoCoreError, ClientError) as exc:
            raise MessagePublishError() from exc

        message_id = response.get("MessageId")

        if not message_id:
            raise MessagePublishError()

        return message_id

    async def send_events_batch(
        self, events: tuple[EventEnvelope, ...]
    ) -> tuple[SQSBatchSendResult, ...]:
        """Send to one standard queue and reconcile every returned batch entry.

        Multiple SQS calls are allowed when a batch exceeds 10 entries or 1 MiB.
        A transport exception means some previously accepted entries may have
        unknown outcomes; the caller must retry idempotently, never mark success.
        """
        if not events:
            raise ValueError("SQS batch must not be empty")
        if self._queue_url.endswith(".fifo"):
            raise ValueError("FIFO SQS batch requires explicit group and deduplication IDs")
        max_bytes = 1_048_576
        encoded = [(event, serialize_event_envelope(event)) for event in events]
        results: list[SQSBatchSendResult | None] = [None] * len(events)
        client = cast(SQSBatchClient, self._client)
        cursor = 0
        while cursor < len(encoded):
            chunk: list[tuple[int, str]] = []
            total = 0
            while cursor < len(encoded) and len(chunk) < 10:
                event, body = encoded[cursor]
                size = len(body.encode("utf-8"))
                if size > max_bytes:
                    results[cursor] = SQSBatchSendResult(
                        event_id=event.event_id,
                        status="permanent",
                        failure_code="MessageTooLarge",
                    )
                    cursor += 1
                    continue
                if chunk and total + size > max_bytes:
                    break
                chunk.append((cursor, body))
                total += size
                cursor += 1
            if not chunk:
                continue
            # Use source index as per-request entry ID; never rely on response order.
            entries = [{"Id": str(i), "MessageBody": body} for i, body in chunk]
            try:
                response = await asyncio.to_thread(
                    client.send_message_batch,
                    QueueUrl=self._queue_url,
                    Entries=entries,
                )
            except (BotoCoreError, ClientError) as exc:
                raise MessagePublishError() from exc

            expected = {str(i) for i, _ in chunk}
            seen: set[str] = set()
            for success in response.get("Successful", []):
                ident = success.get("Id", "")
                if ident not in expected or ident in seen or not success.get("MessageId"):
                    raise MessagePublishError()
                seen.add(ident)
                index = int(ident)
                results[index] = SQSBatchSendResult(
                    event_id=encoded[index][0].event_id, status="sent"
                )
            for failure in response.get("Failed", []):
                ident = failure.get("Id", "")
                if ident not in expected or ident in seen:
                    raise MessagePublishError()
                code = failure.get("Code", "")
                if not code or type(failure.get("SenderFault")) is not bool:
                    raise MessagePublishError()
                seen.add(ident)
                index = int(ident)
                results[index] = SQSBatchSendResult(
                    event_id=encoded[index][0].event_id,
                    status="permanent" if failure["SenderFault"] else "retryable",
                    failure_code=code,
                )
            if seen != expected:
                raise MessagePublishError()
        if any(result is None for result in results):
            raise MessagePublishError()
        return tuple(result for result in results if result is not None)

    async def receive_events(
        self,
        *,
        max_messages: int = 10,
        wait_time_seconds: int = 0,
    ) -> tuple[ReceivedEventMessage, ...]:
        if not 1 <= max_messages <= 10:
            raise ValueError("SQS max messages must be between 1 and 10.")

        if not 0 <= wait_time_seconds <= 20:
            raise ValueError("SQS wait time must be between 0 and 20 seconds.")

        try:
            response = await asyncio.to_thread(
                self._client.receive_message,
                QueueUrl=self._queue_url,
                MaxNumberOfMessages=max_messages,
                WaitTimeSeconds=wait_time_seconds,
            )
        except (BotoCoreError, ClientError) as exc:
            raise MessageReceiveError() from exc

        messages = response.get(
            "Messages",
            [],
        )

        received: list[ReceivedEventMessage] = []

        for message in messages:
            message_id = message.get("MessageId")
            receipt_handle = message.get("ReceiptHandle")
            body = message.get("Body")

            if not message_id or not receipt_handle or body is None:
                raise InvalidMessageError()

            try:
                event = deserialize_event_envelope(body)
            except EventSerializationError as exc:
                raise InvalidMessageError() from exc

            received.append(
                ReceivedEventMessage(
                    message_id=message_id,
                    receipt_handle=receipt_handle,
                    event=event,
                )
            )

        return tuple(received)

    async def delete_message(
        self,
        receipt_handle: str,
    ) -> None:
        normalized_receipt_handle = receipt_handle.strip()

        if not normalized_receipt_handle:
            raise ValueError("SQS receipt handle must not be empty.")

        try:
            await asyncio.to_thread(
                self._client.delete_message,
                QueueUrl=self._queue_url,
                ReceiptHandle=(normalized_receipt_handle),
            )
        except (BotoCoreError, ClientError) as exc:
            raise MessageDeleteError() from exc

    async def close(self) -> None:
        close = getattr(self._client, "close", None)
        if close is not None:
            await asyncio.to_thread(close)
