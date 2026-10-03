from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import NotRequired, Protocol, TypedDict

from botocore.exceptions import ClientError

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
        except ClientError as exc:
            raise MessagePublishError() from exc

        message_id = response.get("MessageId")

        if not message_id:
            raise MessagePublishError()

        return message_id

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
        except ClientError as exc:
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
        except ClientError as exc:
            raise MessageDeleteError() from exc
