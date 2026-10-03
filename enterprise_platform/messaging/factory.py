from __future__ import annotations

from typing import cast

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.eventbridge import (
    EventBridgeClient,
    EventBridgeEventPublisher,
)
from enterprise_platform.messaging.sns import (
    SNSClient,
    SNSEventPublisher,
)
from enterprise_platform.messaging.sqs import (
    SQSClient,
    SQSEventQueue,
)


def create_sqs_event_queue(
    settings: Settings,
    *,
    queue_url: str,
) -> SQSEventQueue:
    """Create an SQS event queue through the platform AWS client factory."""

    client = cast(
        SQSClient,
        AWSClientFactory(settings).sqs(),
    )

    return SQSEventQueue(
        client,
        queue_url=queue_url,
    )


def create_sns_event_publisher(
    settings: Settings,
    *,
    topic_arn: str,
) -> SNSEventPublisher:
    """Create an SNS event publisher through the platform AWS client factory."""

    client = cast(
        SNSClient,
        AWSClientFactory(settings).sns(),
    )

    return SNSEventPublisher(
        client,
        topic_arn=topic_arn,
    )


def create_eventbridge_event_publisher(
    settings: Settings,
    *,
    event_bus_name: str,
) -> EventBridgeEventPublisher:
    """Create an EventBridge publisher through the platform AWS client factory."""

    client = cast(
        EventBridgeClient,
        AWSClientFactory(settings).eventbridge(),
    )

    return EventBridgeEventPublisher(
        client,
        event_bus_name=event_bus_name,
    )
