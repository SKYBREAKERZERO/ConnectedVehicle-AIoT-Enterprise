from __future__ import annotations

import asyncio
import json
from typing import NotRequired, Protocol, TypedDict, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.factory import (
    create_sqs_event_queue,
)
from enterprise_platform.reliability.dlq import (
    DeadLetterPolicy,
)


class SQSCreateQueueResponse(TypedDict):
    QueueUrl: NotRequired[str]


class SQSQueueAttributesResponse(TypedDict):
    Attributes: NotRequired[dict[str, str]]


class SQSAdminClient(Protocol):
    def create_queue(
        self,
        *,
        QueueName: str,
        Attributes: dict[str, str],
    ) -> SQSCreateQueueResponse: ...

    def get_queue_attributes(
        self,
        *,
        QueueUrl: str,
        AttributeNames: list[str],
    ) -> SQSQueueAttributesResponse: ...

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


@pytest.mark.asyncio
async def test_localstack_sqs_redrives_failed_message_to_dlq() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK
    assert settings.aws_endpoint_url is not None

    client = cast(
        SQSAdminClient,
        AWSClientFactory(settings).sqs(),
    )

    suffix = uuid4().hex
    dlq_name = f"connected-vehicle-dlq-{suffix}"
    source_name = f"connected-vehicle-source-{suffix}"

    dlq_url: str | None = None
    source_url: str | None = None

    policy = DeadLetterPolicy(
        max_receive_count=3,
    )

    try:
        dlq_response = client.create_queue(
            QueueName=dlq_name,
            Attributes={
                "MessageRetentionPeriod": "1209600",
            },
        )

        returned_dlq_url = dlq_response.get("QueueUrl")

        assert returned_dlq_url

        dlq_url = normalize_localstack_queue_url(
            returned_dlq_url,
            endpoint_url=settings.aws_endpoint_url,
        )

        attributes_response = client.get_queue_attributes(
            QueueUrl=dlq_url,
            AttributeNames=[
                "QueueArn",
            ],
        )

        dlq_arn = attributes_response.get(
            "Attributes",
            {},
        ).get("QueueArn")

        assert dlq_arn

        redrive_policy = json.dumps(
            {
                "deadLetterTargetArn": dlq_arn,
                "maxReceiveCount": str(policy.max_receive_count),
            }
        )

        source_response = client.create_queue(
            QueueName=source_name,
            Attributes={
                "VisibilityTimeout": "0",
                "RedrivePolicy": redrive_policy,
            },
        )

        returned_source_url = source_response.get("QueueUrl")

        assert returned_source_url

        source_url = normalize_localstack_queue_url(
            returned_source_url,
            endpoint_url=settings.aws_endpoint_url,
        )

        source_queue = create_sqs_event_queue(
            settings,
            queue_url=source_url,
        )

        dlq_queue = create_sqs_event_queue(
            settings,
            queue_url=dlq_url,
        )

        event = create_event_envelope(
            event_type="vehicle.command.requested",
            source="dlq-integration-test",
            payload={
                "vehicle_id": "VIN-DLQ-001",
                "command": "unlock",
            },
        )

        message_id = await source_queue.send_event(event)

        assert message_id

        dlq_messages = ()

        for _ in range(10):
            source_messages = await source_queue.receive_events(
                max_messages=1,
                wait_time_seconds=0,
            )

            if source_messages:
                # Deliberately do not delete the message.
                # This simulates consumer processing failure.
                pass

            dlq_messages = await dlq_queue.receive_events(
                max_messages=1,
                wait_time_seconds=0,
            )

            if dlq_messages:
                break

            await asyncio.sleep(0.1)

        assert len(dlq_messages) == 1
        assert dlq_messages[0].event == event

        await dlq_queue.delete_message(dlq_messages[0].receipt_handle)

    finally:
        if source_url is not None:
            client.delete_queue(
                QueueUrl=source_url,
            )

        if dlq_url is not None:
            client.delete_queue(
                QueueUrl=dlq_url,
            )
