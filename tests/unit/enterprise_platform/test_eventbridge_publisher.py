from __future__ import annotations

from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.eventbridge import (
    EventBridgeEntry,
    EventBridgeEventPublisher,
    EventBridgePutEventsResponse,
)
from enterprise_platform.messaging.exceptions import (
    MessagePublishError,
)
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)


class FakeEventBridgeClient:
    def __init__(self) -> None:
        self.entries: list[EventBridgeEntry] | None = None

    def put_events(
        self,
        *,
        Entries: list[EventBridgeEntry],
    ) -> EventBridgePutEventsResponse:
        self.entries = Entries

        return {
            "FailedEntryCount": 0,
            "Entries": [
                {
                    "EventId": "eventbridge-001",
                }
            ],
        }


class FailedEntryEventBridgeClient(FakeEventBridgeClient):
    def put_events(
        self,
        *,
        Entries: list[EventBridgeEntry],
    ) -> EventBridgePutEventsResponse:
        self.entries = Entries

        return {
            "FailedEntryCount": 1,
            "Entries": [
                {
                    "ErrorCode": "InternalFailure",
                    "ErrorMessage": ("backend-detail-must-not-leak"),
                }
            ],
        }


class FailingEventBridgeClient(FakeEventBridgeClient):
    def put_events(
        self,
        *,
        Entries: list[EventBridgeEntry],
    ) -> EventBridgePutEventsResponse:
        del Entries

        raise ClientError(
            {
                "Error": {
                    "Code": "InternalError",
                    "Message": ("backend-detail-must-not-leak"),
                }
            },
            "PutEvents",
        )


@pytest.mark.asyncio
async def test_eventbridge_publisher_maps_event_envelope() -> None:
    client = FakeEventBridgeClient()

    publisher = EventBridgeEventPublisher(
        client,
        event_bus_name="vehicle-events",
    )

    occurred_at = datetime(
        2026,
        10,
        3,
        4,
        0,
        tzinfo=UTC,
    )

    event = create_event_envelope(
        event_id="event-001",
        event_type="vehicle.command.completed",
        source="command-service",
        occurred_at=occurred_at,
        correlation_id="correlation-001",
        trace_id="trace-001",
        payload={
            "vehicle_id": "VIN001",
            "status": "completed",
        },
    )

    event_id = await publisher.publish_event(event)

    assert event_id == "eventbridge-001"

    assert client.entries == [
        {
            "Source": "command-service",
            "DetailType": ("vehicle.command.completed"),
            "Detail": (serialize_event_envelope(event)),
            "EventBusName": "vehicle-events",
            "Time": occurred_at,
        }
    ]


def test_eventbridge_publisher_rejects_empty_bus_name() -> None:
    with pytest.raises(
        ValueError,
        match=("EventBridge event bus name must not be empty"),
    ):
        EventBridgeEventPublisher(
            FakeEventBridgeClient(),
            event_bus_name="   ",
        )


@pytest.mark.asyncio
async def test_eventbridge_publisher_rejects_failed_entry() -> None:
    publisher = EventBridgeEventPublisher(
        FailedEntryEventBridgeClient(),
        event_bus_name="vehicle-events",
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


@pytest.mark.asyncio
async def test_eventbridge_publisher_hides_backend_failure() -> None:
    publisher = EventBridgeEventPublisher(
        FailingEventBridgeClient(),
        event_bus_name="vehicle-events",
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
