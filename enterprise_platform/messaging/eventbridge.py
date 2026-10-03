from __future__ import annotations

import asyncio
from datetime import datetime
from typing import NotRequired, Protocol, TypedDict

from botocore.exceptions import ClientError

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)


class EventBridgeEntry(TypedDict):
    Source: str
    DetailType: str
    Detail: str
    EventBusName: str
    Time: datetime


class EventBridgeResultEntry(TypedDict):
    EventId: NotRequired[str]
    ErrorCode: NotRequired[str]
    ErrorMessage: NotRequired[str]


class EventBridgePutEventsResponse(TypedDict):
    FailedEntryCount: NotRequired[int]
    Entries: NotRequired[list[EventBridgeResultEntry]]


class EventBridgeClient(Protocol):
    def put_events(
        self,
        *,
        Entries: list[EventBridgeEntry],
    ) -> EventBridgePutEventsResponse: ...


def normalize_event_bus_name(
    event_bus_name: str,
) -> str:
    normalized = event_bus_name.strip()

    if not normalized:
        raise ValueError("EventBridge event bus name must not be empty.")

    return normalized


class EventBridgeEventPublisher:
    """EventBridge publisher for platform EventEnvelope events."""

    def __init__(
        self,
        client: EventBridgeClient,
        *,
        event_bus_name: str,
    ) -> None:
        self._client = client
        self._event_bus_name = normalize_event_bus_name(event_bus_name)

    @property
    def event_bus_name(self) -> str:
        return self._event_bus_name

    async def publish_event(
        self,
        event: EventEnvelope,
    ) -> str:
        detail = serialize_event_envelope(event)

        entry: EventBridgeEntry = {
            "Source": event.source,
            "DetailType": event.event_type,
            "Detail": detail,
            "EventBusName": self._event_bus_name,
            "Time": event.occurred_at,
        }

        try:
            response = await asyncio.to_thread(
                self._client.put_events,
                Entries=[entry],
            )
        except ClientError as exc:
            raise MessagePublishError() from exc

        failed_entry_count = response.get(
            "FailedEntryCount",
            0,
        )

        entries = response.get(
            "Entries",
            [],
        )

        if failed_entry_count != 0 or len(entries) != 1:
            raise MessagePublishError()

        event_id = entries[0].get("EventId")

        if not event_id:
            raise MessagePublishError()

        return event_id
