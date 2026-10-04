from __future__ import annotations

from typing import Protocol

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandId,
)
from connected_vehicle.vehicle import VehicleId


class RemoteCommandRepository(Protocol):
    """Persistence contract for the RemoteCommand aggregate."""

    def add(
        self,
        command: RemoteCommand,
    ) -> None:
        """Add a new command to the current transaction."""
        ...

    async def get_by_id(
        self,
        command_id: RemoteCommandId,
    ) -> RemoteCommand | None:
        """Return a remote command by ID."""
        ...

    async def get_by_id_for_tenant(
        self,
        command_id: RemoteCommandId,
        tenant_id: str,
    ) -> RemoteCommand | None:
        """Return a command only when it belongs to the tenant."""
        ...

    async def get_by_idempotency_key(
        self,
        *,
        tenant_id: str,
        vehicle_id: VehicleId,
        idempotency_key: str,
    ) -> RemoteCommand | None:
        """Return the command created for an idempotent request."""
        ...

    async def get_for_update(
        self,
        command_id: RemoteCommandId,
    ) -> RemoteCommand | None:
        """Load and lock a command row for state transition."""
        ...

    async def save(
        self,
        command: RemoteCommand,
    ) -> bool:
        """Persist aggregate state in the current transaction."""
        ...
