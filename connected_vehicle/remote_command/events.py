from __future__ import annotations

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandStatus,
)
from connected_vehicle.remote_command.wire_contracts import RequestedPayload
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)

REMOTE_COMMAND_REQUESTED_EVENT_TYPE = "vehicle.command.requested"
REMOTE_COMMAND_EVENT_SOURCE = "connected-vehicle.remote-command"
REMOTE_COMMAND_DESTINATION = "vehicle-command"


def create_remote_command_requested_event(
    command: RemoteCommand,
) -> EventEnvelope:
    if command.status is not RemoteCommandStatus.REQUESTED:
        raise ValueError("Remote command requested event requires a command in REQUESTED status.")

    event = create_event_envelope(
        event_id=f"remote-command:{command.id.value}:requested",
        event_type=REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
        source=REMOTE_COMMAND_EVENT_SOURCE,
        payload={
            "command_id": command.id.value,
            "vehicle_id": command.vehicle_id.value,
            "tenant_id": command.tenant_id,
            "command_type": command.command_type.value,
            "status": command.status.value,
            "created_at": command.created_at.isoformat(),
            "expires_at": command.expires_at.isoformat(),
        },
    )

    RequestedPayload.model_validate(event.payload)
    return event
