from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandStatus,
)


class RemoteCommandDispatchAction(StrEnum):
    QUEUE = "queue"
    START_DISPATCH = "start_dispatch"
    PUBLISH = "publish"
    ACKNOWLEDGE = "acknowledge"
    EXPIRE = "expire"


def decide_remote_command_dispatch_action(
    command: RemoteCommand,
    *,
    now: datetime | None = None,
) -> RemoteCommandDispatchAction:
    timestamp = now if now is not None else datetime.now(UTC)

    if timestamp.tzinfo is None:
        raise ValueError("Remote command dispatch decision time must be timezone-aware.")

    if (
        command.status
        in {
            RemoteCommandStatus.SENT,
            RemoteCommandStatus.ACKNOWLEDGED,
        }
        or command.is_terminal
    ):
        return RemoteCommandDispatchAction.ACKNOWLEDGE

    if command.is_expired(at=timestamp):
        return RemoteCommandDispatchAction.EXPIRE

    if command.status is RemoteCommandStatus.REQUESTED:
        return RemoteCommandDispatchAction.QUEUE

    if command.status is RemoteCommandStatus.QUEUED:
        return RemoteCommandDispatchAction.START_DISPATCH

    if command.status is RemoteCommandStatus.DISPATCHING:
        return RemoteCommandDispatchAction.PUBLISH

    raise RuntimeError(f"Remote command dispatch state is not handled: {command.status.value!r}.")
