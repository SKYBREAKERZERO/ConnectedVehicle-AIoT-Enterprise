from __future__ import annotations

from typing import Protocol

from connected_vehicle.remote_command.domain import RemoteCommand


class RemoteCommandPublisher(Protocol):
    """Transport-neutral outbound remote-command publisher."""

    async def publish(
        self,
        command: RemoteCommand,
    ) -> None:
        """Publish one command to the vehicle transport."""
        ...
