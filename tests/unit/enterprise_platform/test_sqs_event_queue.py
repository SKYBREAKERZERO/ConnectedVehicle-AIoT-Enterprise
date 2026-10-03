from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.exceptions import (
    InvalidMessageError,
    MessageDeleteError,
    MessagePublishError,
    MessageReceiveError,
)
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)
from enterprise_platform.messaging.sqs import (
    SQSEventQueue,
    SQSReceiveResponse,
    SQSSendResponse,
)


class FakeSQSClient:
    def __init__(self) -> None:
        self.sent_body: str | None = None
        self.deleted_receipt_handle: str | None = None
        self.receive_response: SQSReceiveResponse = {}

    def send_message(
        self,
        *,
        QueueUrl: str,
        MessageBody: str,
    ) -> SQSSendResponse:
        assert QueueUrl == "https://queue.example/test"

        self.sent_body = MessageBody

        return {
            "MessageId": "message-001",
        }

    def receive_message(
        self,
        *,
        QueueUrl: str,
        MaxNumberOfMessages: int,
        WaitTimeSeconds: int,
    ) -> SQSReceiveResponse:
        assert QueueUrl == "https://queue.example/test"
        assert 1 <= MaxNumberOfMessages <= 10
        assert 0 <= WaitTimeSeconds <= 20

        return self.receive_response

    def delete_message(
        self,
        *,
        QueueUrl: str,
        ReceiptHandle: str,
    ) -> object:
        assert QueueUrl == "https://queue.example/test"

        self.deleted_receipt_handle = ReceiptHandle

        return {}


class FailingSQSClient(FakeSQSClient):
    def __init__(
        self,
        operation: str,
    ) -> None:
        super().__init__()
        self._operation = operation

    def _raise(self, operation: str) -> None:
        raise ClientError(
            {
                "Error": {
                    "Code": "InternalError",
                    "Message": ("backend-detail-must-not-leak"),
                }
            },
            operation,
        )

    def send_message(
        self,
        *,
        QueueUrl: str,
        MessageBody: str,
    ) -> SQSSendResponse:
        if self._operation == "send":
            self._raise("SendMessage")

        return super().send_message(
            QueueUrl=QueueUrl,
            MessageBody=MessageBody,
        )

    def receive_message(
        self,
        *,
        QueueUrl: str,
        MaxNumberOfMessages: int,
        WaitTimeSeconds: int,
    ) -> SQSReceiveResponse:
        if self._operation == "receive":
            self._raise("ReceiveMessage")

        return super().receive_message(
            QueueUrl=QueueUrl,
            MaxNumberOfMessages=MaxNumberOfMessages,
            WaitTimeSeconds=WaitTimeSeconds,
        )

    def delete_message(
        self,
        *,
        QueueUrl: str,
        ReceiptHandle: str,
    ) -> object:
        if self._operation == "delete":
            self._raise("DeleteMessage")

        return super().delete_message(
            QueueUrl=QueueUrl,
            ReceiptHandle=ReceiptHandle,
        )


def create_queue(
    client: FakeSQSClient,
) -> SQSEventQueue:
    return SQSEventQueue(
        client,
        queue_url="https://queue.example/test",
    )


@pytest.mark.asyncio
async def test_sqs_queue_sends_serialized_event() -> None:
    client = FakeSQSClient()
    queue = create_queue(client)

    event = create_event_envelope(
        event_id="event-001",
        event_type="vehicle.command.requested",
        source="vehicle-api",
        correlation_id="correlation-001",
        trace_id="trace-001",
        payload={
            "vehicle_id": "VIN001",
            "command": "unlock",
        },
    )

    message_id = await queue.send_event(event)

    assert message_id == "message-001"
    assert client.sent_body == (serialize_event_envelope(event))


@pytest.mark.asyncio
async def test_sqs_queue_receives_event() -> None:
    client = FakeSQSClient()
    queue = create_queue(client)

    event = create_event_envelope(
        event_id="event-002",
        event_type="vehicle.registered",
        source="vehicle-service",
        payload={
            "vehicle_id": "VIN002",
        },
    )

    client.receive_response = {
        "Messages": [
            {
                "MessageId": "message-002",
                "ReceiptHandle": "receipt-002",
                "Body": serialize_event_envelope(event),
            }
        ]
    }

    messages = await queue.receive_events()

    assert len(messages) == 1

    message = messages[0]

    assert message.message_id == "message-002"
    assert message.receipt_handle == "receipt-002"
    assert message.event == event


@pytest.mark.asyncio
async def test_sqs_queue_returns_empty_tuple_when_no_messages_exist() -> None:
    client = FakeSQSClient()
    queue = create_queue(client)

    assert await queue.receive_events() == ()


@pytest.mark.asyncio
async def test_sqs_queue_deletes_message() -> None:
    client = FakeSQSClient()
    queue = create_queue(client)

    await queue.delete_message("receipt-003")

    assert client.deleted_receipt_handle == "receipt-003"


@pytest.mark.asyncio
async def test_sqs_queue_rejects_invalid_received_event() -> None:
    client = FakeSQSClient()
    queue = create_queue(client)

    client.receive_response = {
        "Messages": [
            {
                "MessageId": "message-004",
                "ReceiptHandle": "receipt-004",
                "Body": "not-json",
            }
        ]
    }

    with pytest.raises(InvalidMessageError):
        await queue.receive_events()


@pytest.mark.parametrize(
    ("operation", "error_type"),
    [
        ("send", MessagePublishError),
        ("receive", MessageReceiveError),
        ("delete", MessageDeleteError),
    ],
)
@pytest.mark.asyncio
async def test_sqs_queue_hides_backend_failures(
    operation: str,
    error_type: type[Exception],
) -> None:
    client = FailingSQSClient(operation)
    queue = create_queue(client)

    if operation == "send":
        with pytest.raises(error_type) as exc_info:
            await queue.send_event(
                create_event_envelope(
                    event_type="vehicle.test",
                    source="test-service",
                    payload={},
                )
            )

    elif operation == "receive":
        with pytest.raises(error_type) as exc_info:
            await queue.receive_events()

    else:
        with pytest.raises(error_type) as exc_info:
            await queue.delete_message("receipt-005")

    assert "backend-detail-must-not-leak" not in str(exc_info.value)
