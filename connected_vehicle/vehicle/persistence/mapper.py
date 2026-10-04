from __future__ import annotations

from connected_vehicle.vehicle.domain import (
    VIN,
    Vehicle,
    VehicleId,
    VehicleStatus,
)
from connected_vehicle.vehicle.persistence.models import VehicleModel


def vehicle_to_model(
    vehicle: Vehicle,
) -> VehicleModel:
    return VehicleModel(
        id=vehicle.id.value,
        vin=vehicle.vin.value,
        tenant_id=vehicle.tenant_id,
        status=vehicle.status.value,
        created_at=vehicle.created_at,
        updated_at=vehicle.updated_at,
    )


def vehicle_from_model(
    model: VehicleModel,
) -> Vehicle:
    return Vehicle(
        id=VehicleId(model.id),
        vin=VIN(model.vin),
        tenant_id=model.tenant_id,
        status=VehicleStatus(model.status),
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def apply_vehicle_to_model(
    model: VehicleModel,
    vehicle: Vehicle,
) -> None:
    if model.id != vehicle.id.value:
        raise ValueError("Cannot apply a Vehicle to a model with a different ID.")

    model.vin = vehicle.vin.value
    model.tenant_id = vehicle.tenant_id
    model.status = vehicle.status.value
    model.created_at = vehicle.created_at
    model.updated_at = vehicle.updated_at
