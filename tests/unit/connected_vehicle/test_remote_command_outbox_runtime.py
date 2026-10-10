from __future__ import annotations

import pytest

import connected_vehicle.remote_command.outbox_runtime as outbox_runtime
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
)
from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from tests.settings_helpers import isolated_settings


class FakeSQSEventQueue:
    def __init__(self) -> None:
        self.events: list[EventEnvelope] = []

    async def send_event(
        self,
        event: EventEnvelope,
    ) -> str:
        self.events.append(event)

        return "message-001"


@pytest.mark.asyncio
async def test_remote_command_destination_routes_to_configured_sqs_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = FakeSQSEventQueue()
    resolved_queue_names: list[str] = []

    def fake_create_named_sqs_event_queue(
        settings: Settings,
        *,
        queue_name: str,
    ) -> FakeSQSEventQueue:
        del settings

        resolved_queue_names.append(queue_name)

        return queue

    monkeypatch.setattr(
        outbox_runtime,
        "create_named_sqs_event_queue",
        fake_create_named_sqs_event_queue,
    )

    settings = isolated_settings(
        vehicle_command_queue_name=("connected-vehicle-command-test"),
        _env_file=None,
    )

    destinations = outbox_runtime.create_remote_command_outbox_destinations(settings)

    event = create_event_envelope(
        event_id="remote-command:test-command:requested",
        event_type="vehicle.command.requested",
        source="connected-vehicle.remote-command",
        payload={
            "command_id": "test-command",
        },
    )

    publisher = destinations.resolve(REMOTE_COMMAND_DESTINATION)

    message_id = await publisher(event)

    assert resolved_queue_names == ["connected-vehicle-command-test"]
    assert queue.events == [event]
    assert message_id == "message-001"


def test_remote_command_destination_is_logical_not_physical() -> None:
    assert REMOTE_COMMAND_DESTINATION == "vehicle-command"
    assert REMOTE_COMMAND_DESTINATION != "connected-vehicle-command"
