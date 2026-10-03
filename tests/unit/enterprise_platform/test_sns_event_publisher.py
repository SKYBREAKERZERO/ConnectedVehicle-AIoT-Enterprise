from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.exceptions import (
    MessagePublishError,
)
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)
from enterprise_platform.messaging.sns import (
    SNSEventPublisher,
    SNSMessageAttributeValue,
    SNSPublishResponse,
)


class FakeSNSClient:
    def __init__(self) -> None:
        self.topic_arn: str | None = None
        self.message: str | None = None
        self.attributes: dict[str, SNSMessageAttributeValue] | None = None

    def publish(
        self,
        *,
        TopicArn: str,
        Message: str,
        MessageAttributes: dict[
            str,
            SNSMessageAttributeValue,
        ],
    ) -> SNSPublishResponse:
        self.topic_arn = TopicArn
        self.message = Message
        self.attributes = MessageAttributes

        return {
            "MessageId": "sns-message-001",
        }


class MissingMessageIdSNSClient(FakeSNSClient):
    def publish(
        self,
        *,
        TopicArn: str,
        Message: str,
        MessageAttributes: dict[
            str,
            SNSMessageAttributeValue,
        ],
    ) -> SNSPublishResponse:
        super().publish(
            TopicArn=TopicArn,
            Message=Message,
            MessageAttributes=MessageAttributes,
        )

        return {}


class FailingSNSClient(FakeSNSClient):
    def publish(
        self,
        *,
        TopicArn: str,
        Message: str,
        MessageAttributes: dict[
            str,
            SNSMessageAttributeValue,
        ],
    ) -> SNSPublishResponse:
        del TopicArn, Message, MessageAttributes

        raise ClientError(
            {
                "Error": {
                    "Code": "InternalError",
                    "Message": ("backend-detail-must-not-leak"),
                }
            },
            "Publish",
        )


@pytest.mark.asyncio
async def test_sns_publisher_serializes_event() -> None:
    client = FakeSNSClient()

    publisher = SNSEventPublisher(
        client,
        topic_arn=("arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"),
    )

    event = create_event_envelope(
        event_id="event-001",
        event_type="vehicle.command.completed",
        source="command-service",
        correlation_id="correlation-001",
        trace_id="trace-001",
        payload={
            "vehicle_id": "VIN001",
            "status": "completed",
        },
    )

    message_id = await publisher.publish_event(event)

    assert message_id == "sns-message-001"

    assert client.message == (serialize_event_envelope(event))


@pytest.mark.asyncio
async def test_sns_publisher_adds_filterable_message_attributes() -> None:
    client = FakeSNSClient()

    publisher = SNSEventPublisher(
        client,
        topic_arn=("arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"),
    )

    event = create_event_envelope(
        event_type="vehicle.command.completed",
        source="command-service",
        schema_version="1.0",
        correlation_id="correlation-002",
        trace_id="trace-002",
        payload={},
    )

    await publisher.publish_event(event)

    assert client.attributes == {
        "event_type": {
            "DataType": "String",
            "StringValue": ("vehicle.command.completed"),
        },
        "schema_version": {
            "DataType": "String",
            "StringValue": "1.0",
        },
        "source": {
            "DataType": "String",
            "StringValue": "command-service",
        },
        "correlation_id": {
            "DataType": "String",
            "StringValue": "correlation-002",
        },
        "trace_id": {
            "DataType": "String",
            "StringValue": "trace-002",
        },
    }


@pytest.mark.asyncio
async def test_sns_publisher_omits_missing_optional_trace_attributes() -> None:
    client = FakeSNSClient()

    publisher = SNSEventPublisher(
        client,
        topic_arn=("arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"),
    )

    event = create_event_envelope(
        event_type="vehicle.registered",
        source="vehicle-service",
        correlation_id=None,
        trace_id=None,
        payload={},
    )

    await publisher.publish_event(event)

    assert client.attributes is not None
    assert "correlation_id" not in client.attributes
    assert "trace_id" not in client.attributes


def test_sns_publisher_rejects_empty_topic_arn() -> None:
    with pytest.raises(
        ValueError,
        match="SNS topic ARN must not be empty",
    ):
        SNSEventPublisher(
            FakeSNSClient(),
            topic_arn="   ",
        )


@pytest.mark.asyncio
async def test_sns_publisher_rejects_missing_message_id() -> None:
    publisher = SNSEventPublisher(
        MissingMessageIdSNSClient(),
        topic_arn=("arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"),
    )

    with pytest.raises(MessagePublishError):
        await publisher.publish_event(
            create_event_envelope(
                event_type="vehicle.test",
                source="test-service",
                payload={},
            )
        )


@pytest.mark.asyncio
async def test_sns_publisher_hides_backend_failure() -> None:
    publisher = SNSEventPublisher(
        FailingSNSClient(),
        topic_arn=("arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"),
    )

    with pytest.raises(MessagePublishError) as exc_info:
        await publisher.publish_event(
            create_event_envelope(
                event_type="vehicle.test",
                source="test-service",
                payload={},
            )
        )

    assert "backend-detail-must-not-leak" not in str(exc_info.value)
