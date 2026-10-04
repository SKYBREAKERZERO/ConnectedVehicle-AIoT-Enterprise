from __future__ import annotations

from typing import Protocol

from connected_vehicle.vehicle.domain import (
    VIN,
    Vehicle,
    VehicleId,
)


class VehicleRepository(Protocol):
    """Persistence contract for the Vehicle aggregate."""

    def add(
        self,
        vehicle: Vehicle,
    ) -> None:
        """Add a new vehicle to the current transaction."""
        ...

    async def get_by_id(
        self,
        vehicle_id: VehicleId,
    ) -> Vehicle | None:
        """Return a vehicle by its globally unique identifier."""
        ...

    async def get_by_vin(
        self,
        vin: VIN,
    ) -> Vehicle | None:
        """Return a vehicle by VIN."""
        ...

    async def get_by_id_for_tenant(
        self,
        vehicle_id: VehicleId,
        tenant_id: str,
    ) -> Vehicle | None:
        """Return a vehicle only when it belongs to the tenant."""
        ...

    async def save(
        self,
        vehicle: Vehicle,
    ) -> bool:
        """Persist aggregate state inside the current transaction."""
        ...
