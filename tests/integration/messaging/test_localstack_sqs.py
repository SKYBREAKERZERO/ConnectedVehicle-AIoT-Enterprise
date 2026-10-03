from __future__ import annotations

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


class SQSCreateQueueResponse(TypedDict):
    QueueUrl: NotRequired[str]


class SQSIntegrationClient(Protocol):
    def create_queue(
        self,
        *,
        QueueName: str,
    ) -> SQSCreateQueueResponse: ...

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
    """Keep the queue path but use the host-visible LocalStack endpoint."""

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
async def test_localstack_sqs_event_round_trip() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK
    assert settings.aws_endpoint_url is not None

    client = cast(
        SQSIntegrationClient,
        AWSClientFactory(settings).sqs(),
    )

    queue_name = f"connected-vehicle-integration-{uuid4().hex}"

    queue_url: str | None = None

    try:
        response = client.create_queue(
            QueueName=queue_name,
        )

        returned_queue_url = response.get("QueueUrl")

        assert returned_queue_url

        queue_url = normalize_localstack_queue_url(
            returned_queue_url,
            endpoint_url=settings.aws_endpoint_url,
        )

        queue = create_sqs_event_queue(
            settings,
            queue_url=queue_url,
        )

        event = create_event_envelope(
            event_type="vehicle.command.requested",
            source="integration-test",
            correlation_id="correlation-sqs-001",
            trace_id="trace-sqs-001",
            payload={
                "vehicle_id": "VIN-INTEGRATION-001",
                "command": "unlock",
            },
        )

        message_id = await queue.send_event(event)

        assert message_id

        messages = await queue.receive_events(
            max_messages=1,
            wait_time_seconds=1,
        )

        assert len(messages) == 1

        received = messages[0]

        assert received.event == event

        await queue.delete_message(received.receipt_handle)

    finally:
        if queue_url is not None:
            client.delete_queue(
                QueueUrl=queue_url,
            )
