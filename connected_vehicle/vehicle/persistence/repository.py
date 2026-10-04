from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from connected_vehicle.vehicle.domain import (
    VIN,
    Vehicle,
    VehicleId,
)
from connected_vehicle.vehicle.persistence.mapper import (
    apply_vehicle_to_model,
    vehicle_from_model,
    vehicle_to_model,
)
from connected_vehicle.vehicle.persistence.models import VehicleModel


class SQLAlchemyVehicleRepository:
    """SQLAlchemy persistence adapter for the Vehicle aggregate."""

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self._session = session

    def add(
        self,
        vehicle: Vehicle,
    ) -> None:
        model = vehicle_to_model(vehicle)
        self._session.add(model)

    async def get_by_id(
        self,
        vehicle_id: VehicleId,
    ) -> Vehicle | None:
        statement = select(VehicleModel).where(VehicleModel.id == vehicle_id.value)

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return vehicle_from_model(model)

    async def get_by_vin(
        self,
        vin: VIN,
    ) -> Vehicle | None:
        statement = select(VehicleModel).where(VehicleModel.vin == vin.value)

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return vehicle_from_model(model)

    async def get_by_id_for_tenant(
        self,
        vehicle_id: VehicleId,
        tenant_id: str,
    ) -> Vehicle | None:
        normalized_tenant_id = tenant_id.strip()

        if not normalized_tenant_id:
            raise ValueError("Tenant ID must not be empty.")

        statement = select(VehicleModel).where(
            VehicleModel.id == vehicle_id.value,
            VehicleModel.tenant_id == normalized_tenant_id,
        )

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return vehicle_from_model(model)

    async def save(
        self,
        vehicle: Vehicle,
    ) -> bool:
        statement = select(VehicleModel).where(VehicleModel.id == vehicle.id.value)

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return False

        apply_vehicle_to_model(
            model,
            vehicle,
        )

        return True
