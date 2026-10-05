from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from connected_vehicle.remote_command.domain import (
    RemoteCommandId,
)
from connected_vehicle.remote_command.event_handler import (
    RemoteCommandRequestedEventHandler,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_EVENT_SOURCE,
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
)
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from enterprise_platform.messaging.exceptions import (
    InvalidMessageError,
)


@dataclass
class FakeDispatcher:
    dispatched: list[RemoteCommandId] = field(default_factory=list)

    async def dispatch(
        self,
        command_id: RemoteCommandId,
    ) -> object:
        self.dispatched.append(command_id)

        return object()


def create_requested_event(
    *,
    command_id: RemoteCommandId | None = None,
    event_id: str | None = None,
    event_type: str = REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
    source: str = REMOTE_COMMAND_EVENT_SOURCE,
    schema_version: str = "1.0",
    payload: dict[str, object] | None = None,
) -> EventEnvelope:
    resolved_command_id = command_id if command_id is not None else RemoteCommandId.new()

    resolved_event_id = (
        event_id
        if event_id is not None
        else (f"remote-command:{resolved_command_id.value}:requested")
    )

    resolved_payload = (
        payload
        if payload is not None
        else {
            "command_id": resolved_command_id.value,
        }
    )

    return create_event_envelope(
        event_id=resolved_event_id,
        event_type=event_type,
        source=source,
        schema_version=schema_version,
        payload=resolved_payload,
    )


@pytest.mark.asyncio
async def test_requested_event_dispatches_command_id() -> None:
    dispatcher = FakeDispatcher()

    handler = RemoteCommandRequestedEventHandler(dispatcher)

    command_id = RemoteCommandId.new()

    event = create_requested_event(command_id=command_id)

    await handler(event)

    assert dispatcher.dispatched == [command_id]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event_type", "source", "schema_version"),
    [
        (
            "vehicle.command.unknown",
            REMOTE_COMMAND_EVENT_SOURCE,
            "1.0",
        ),
        (
            REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
            "another-service",
            "1.0",
        ),
        (
            REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
            REMOTE_COMMAND_EVENT_SOURCE,
            "2.0",
        ),
    ],
)
async def test_wrong_event_contract_is_rejected(
    event_type: str,
    source: str,
    schema_version: str,
) -> None:
    dispatcher = FakeDispatcher()

    handler = RemoteCommandRequestedEventHandler(dispatcher)

    event = create_requested_event(
        event_type=event_type,
        source=source,
        schema_version=schema_version,
    )

    with pytest.raises(InvalidMessageError):
        await handler(event)

    assert dispatcher.dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "command_id": 123,
        },
        {
            "command_id": "",
        },
        {
            "command_id": "not-a-uuid",
        },
    ],
)
async def test_invalid_command_id_is_rejected(
    payload: dict[str, object],
) -> None:
    dispatcher = FakeDispatcher()

    handler = RemoteCommandRequestedEventHandler(dispatcher)

    event = create_requested_event(payload=payload)

    with pytest.raises(InvalidMessageError):
        await handler(event)

    assert dispatcher.dispatched == []


@pytest.mark.asyncio
async def test_event_id_must_match_command_id() -> None:
    dispatcher = FakeDispatcher()

    handler = RemoteCommandRequestedEventHandler(dispatcher)

    command_id = RemoteCommandId.new()

    event = create_requested_event(
        command_id=command_id,
        event_id=(f"remote-command:{RemoteCommandId.new().value}:requested"),
    )

    with pytest.raises(InvalidMessageError):
        await handler(event)

    assert dispatcher.dispatched == []
