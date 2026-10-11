from __future__ import annotations

import json
from hashlib import sha256
from typing import Protocol

from pydantic import ValidationError

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
from connected_vehicle.remote_command.wire_contracts import RequestedPayload
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
        *,
        expected: RequestedPayload,
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

        try:
            expected = RequestedPayload.model_validate(dict(event.payload))
            command_id = RemoteCommandId(str(expected.command_id))
        except (ValidationError, InvalidRemoteCommandIdError) as exc:
            raise InvalidMessageError() from exc

        expected_event_id = f"remote-command:{command_id.value}:requested"

        if event.event_id != expected_event_id:
            raise InvalidMessageError()

        await self._dispatcher.dispatch(command_id, expected=expected)


def dispatch_idempotency_key(event: EventEnvelope) -> str:
    # Exclude trace/receipt metadata, include all immutable dispatch claims.
    body = json.dumps(
        {
            "source": event.source,
            "type": event.event_type,
            "version": event.schema_version,
            "payload": dict(event.payload),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"dispatch:v2:{event.event_id}:{sha256(body.encode()).hexdigest()}"
