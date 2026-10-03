from __future__ import annotations

from unittest.mock import Mock, patch

from botocore.client import BaseClient

from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.factory import (
    create_eventbridge_event_publisher,
    create_sns_event_publisher,
    create_sqs_event_queue,
)


def test_create_sqs_event_queue_uses_platform_client_factory() -> None:
    settings = Settings()

    fake_client = Mock(spec=BaseClient)

    with patch("enterprise_platform.messaging.factory.AWSClientFactory") as factory_type:
        factory = factory_type.return_value
        factory.sqs.return_value = fake_client

        queue = create_sqs_event_queue(
            settings,
            queue_url="https://queue.example/test",
        )

    assert queue.queue_url == ("https://queue.example/test")

    factory_type.assert_called_once_with(settings)
    factory.sqs.assert_called_once_with()


def test_create_sns_event_publisher_uses_platform_client_factory() -> None:
    settings = Settings()

    fake_client = Mock(spec=BaseClient)

    topic_arn = "arn:aws:sns:ap-northeast-1:000000000000:vehicle-events"

    with patch("enterprise_platform.messaging.factory.AWSClientFactory") as factory_type:
        factory = factory_type.return_value
        factory.sns.return_value = fake_client

        publisher = create_sns_event_publisher(
            settings,
            topic_arn=topic_arn,
        )

    assert publisher.topic_arn == topic_arn

    factory_type.assert_called_once_with(settings)
    factory.sns.assert_called_once_with()


def test_create_eventbridge_publisher_uses_platform_client_factory() -> None:
    settings = Settings()

    fake_client = Mock(spec=BaseClient)

    with patch("enterprise_platform.messaging.factory.AWSClientFactory") as factory_type:
        factory = factory_type.return_value
        factory.eventbridge.return_value = fake_client

        publisher = create_eventbridge_event_publisher(
            settings,
            event_bus_name="vehicle-events",
        )

    assert publisher.event_bus_name == "vehicle-events"

    factory_type.assert_called_once_with(settings)
    factory.eventbridge.assert_called_once_with()
