from __future__ import annotations

from typing import Protocol, cast
from uuid import uuid4

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.messaging.factory import (
    create_eventbridge_event_publisher,
)


class EventBridgeIntegrationClient(Protocol):
    def create_event_bus(
        self,
        *,
        Name: str,
    ) -> object: ...

    def delete_event_bus(
        self,
        *,
        Name: str,
    ) -> object: ...


@pytest.mark.asyncio
async def test_localstack_eventbridge_publish() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK

    client = cast(
        EventBridgeIntegrationClient,
        AWSClientFactory(settings).eventbridge(),
    )

    event_bus_name = f"connected-vehicle-integration-{uuid4().hex}"

    event_bus_created = False

    try:
        client.create_event_bus(
            Name=event_bus_name,
        )

        event_bus_created = True

        publisher = create_eventbridge_event_publisher(
            settings,
            event_bus_name=event_bus_name,
        )

        event = create_event_envelope(
            event_type="vehicle.command.completed",
            source="integration-test",
            correlation_id=("correlation-eventbridge-001"),
            trace_id="trace-eventbridge-001",
            payload={
                "vehicle_id": ("VIN-INTEGRATION-001"),
                "command": "unlock",
                "status": "completed",
            },
        )

        event_id = await publisher.publish_event(event)

        assert event_id

    finally:
        if event_bus_created:
            client.delete_event_bus(
                Name=event_bus_name,
            )
