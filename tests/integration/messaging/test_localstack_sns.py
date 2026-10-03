from __future__ import annotations

from typing import NotRequired, Protocol, TypedDict, cast
from uuid import uuid4

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.messaging.factory import create_sns_event_publisher


class SNSCreateTopicResponse(TypedDict):
    TopicArn: NotRequired[str]


class SNSIntegrationClient(Protocol):
    def create_topic(
        self,
        *,
        Name: str,
    ) -> SNSCreateTopicResponse: ...

    def delete_topic(
        self,
        *,
        TopicArn: str,
    ) -> object: ...


@pytest.mark.asyncio
async def test_localstack_sns_publish_round_trip() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK

    client = cast(
        SNSIntegrationClient,
        AWSClientFactory(settings).sns(),
    )

    topic_name = f"connected-vehicle-integration-{uuid4().hex}"

    topic_arn: str | None = None

    try:
        response = client.create_topic(
            Name=topic_name,
        )

        topic_arn = response.get("TopicArn")

        assert topic_arn

        publisher = create_sns_event_publisher(
            settings,
            topic_arn=topic_arn,
        )

        event = create_event_envelope(
            event_type="vehicle.command.completed",
            source="integration-test",
            correlation_id="correlation-sns-001",
            trace_id="trace-sns-001",
            payload={
                "vehicle_id": "VIN-INTEGRATION-001",
                "command": "unlock",
                "status": "completed",
            },
        )

        message_id = await publisher.publish_event(event)

        assert message_id

    finally:
        if topic_arn is not None:
            client.delete_topic(
                TopicArn=topic_arn,
            )
