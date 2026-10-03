from __future__ import annotations

import asyncio
from typing import NotRequired, Protocol, TypedDict

from botocore.exceptions import ClientError

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)


class SNSMessageAttributeValue(TypedDict):
    DataType: str
    StringValue: str


class SNSPublishResponse(TypedDict):
    MessageId: NotRequired[str]


class SNSClient(Protocol):
    def publish(
        self,
        *,
        TopicArn: str,
        Message: str,
        MessageAttributes: dict[str, SNSMessageAttributeValue],
    ) -> SNSPublishResponse: ...


def normalize_topic_arn(topic_arn: str) -> str:
    normalized = topic_arn.strip()

    if not normalized:
        raise ValueError("SNS topic ARN must not be empty.")

    return normalized


def create_sns_message_attributes(
    event: EventEnvelope,
) -> dict[str, SNSMessageAttributeValue]:
    attributes: dict[str, SNSMessageAttributeValue] = {
        "event_type": {
            "DataType": "String",
            "StringValue": event.event_type,
        },
        "schema_version": {
            "DataType": "String",
            "StringValue": event.schema_version,
        },
        "source": {
            "DataType": "String",
            "StringValue": event.source,
        },
    }

    if event.correlation_id is not None:
        attributes["correlation_id"] = {
            "DataType": "String",
            "StringValue": event.correlation_id,
        }

    if event.trace_id is not None:
        attributes["trace_id"] = {
            "DataType": "String",
            "StringValue": event.trace_id,
        }

    return attributes


class SNSEventPublisher:
    """SNS publisher for platform EventEnvelope events."""

    def __init__(
        self,
        client: SNSClient,
        *,
        topic_arn: str,
    ) -> None:
        self._client = client
        self._topic_arn = normalize_topic_arn(topic_arn)

    @property
    def topic_arn(self) -> str:
        return self._topic_arn

    async def publish_event(
        self,
        event: EventEnvelope,
    ) -> str:
        message = serialize_event_envelope(event)

        attributes = create_sns_message_attributes(event)

        try:
            response = await asyncio.to_thread(
                self._client.publish,
                TopicArn=self._topic_arn,
                Message=message,
                MessageAttributes=attributes,
            )
        except ClientError as exc:
            raise MessagePublishError() from exc

        message_id = response.get("MessageId")

        if not message_id:
            raise MessagePublishError()

        return message_id
