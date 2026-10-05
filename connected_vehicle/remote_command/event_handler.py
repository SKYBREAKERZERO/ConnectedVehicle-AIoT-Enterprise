from __future__ import annotations

from typing import Protocol

from connected_vehicle.remote_command.domain import (
    RemoteCommandId,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_EVENT_SOURCE,
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
)
from connected_vehicle.remote_command.exceptions import (
    InvalidRemoteCommandIdError,
)
from enterprise_platform.messaging.envelope import (
    EventEnvelope,
)
from enterprise_platform.messaging.exceptions import (
    InvalidMessageError,
)

_REMOTE_COMMAND_REQUESTED_SCHEMA_VERSION = "1.0"


class RemoteCommandDispatcher(Protocol):
    async def dispatch(
        self,
        command_id: RemoteCommandId,
    ) -> object: ...


class RemoteCommandRequestedEventHandler:
    """Validate a requested event and dispatch its command."""

    def __init__(
        self,
        dispatcher: RemoteCommandDispatcher,
    ) -> None:
        self._dispatcher = dispatcher

    async def __call__(
        self,
        event: EventEnvelope,
    ) -> None:
        if event.event_type != REMOTE_COMMAND_REQUESTED_EVENT_TYPE:
            raise InvalidMessageError()

        if event.source != REMOTE_COMMAND_EVENT_SOURCE:
            raise InvalidMessageError()

        if event.schema_version != _REMOTE_COMMAND_REQUESTED_SCHEMA_VERSION:
            raise InvalidMessageError()

        raw_command_id = event.payload.get("command_id")

        if not isinstance(raw_command_id, str):
            raise InvalidMessageError()

        try:
            command_id = RemoteCommandId(raw_command_id)
        except InvalidRemoteCommandIdError as exc:
            raise InvalidMessageError() from exc

        expected_event_id = f"remote-command:{command_id.value}:requested"

        if event.event_id != expected_event_id:
            raise InvalidMessageError()

        await self._dispatcher.dispatch(command_id)
