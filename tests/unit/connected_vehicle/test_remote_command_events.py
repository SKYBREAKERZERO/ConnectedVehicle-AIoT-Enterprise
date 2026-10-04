from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.remote_command import (
    RemoteCommand,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
    REMOTE_COMMAND_EVENT_SOURCE,
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
    create_remote_command_requested_event,
)
from connected_vehicle.vehicle import VehicleId


def create_command() -> RemoteCommand:
    return RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="request-001",
        now=datetime(
            2030,
            1,
            1,
            12,
            0,
            tzinfo=UTC,
        ),
    )


def test_create_remote_command_requested_event() -> None:
    command = create_command()

    event = create_remote_command_requested_event(command)

    assert event.event_id == f"remote-command:{command.id.value}:requested"
    assert event.event_type == REMOTE_COMMAND_REQUESTED_EVENT_TYPE
    assert event.source == REMOTE_COMMAND_EVENT_SOURCE

    assert event.payload == {
        "command_id": command.id.value,
        "vehicle_id": command.vehicle_id.value,
        "tenant_id": command.tenant_id,
        "command_type": RemoteCommandType.LOCK.value,
        "status": RemoteCommandStatus.REQUESTED.value,
        "created_at": command.created_at.isoformat(),
        "expires_at": command.expires_at.isoformat(),
    }

    assert REMOTE_COMMAND_DESTINATION == "vehicle-command"


def test_requested_event_rejects_non_requested_command() -> None:
    command = create_command()

    queued = command.transition_to(
        RemoteCommandStatus.QUEUED,
        now=command.updated_at + timedelta(seconds=1),
    )

    with pytest.raises(
        ValueError,
        match="requires a command in REQUESTED status",
    ):
        create_remote_command_requested_event(queued)
