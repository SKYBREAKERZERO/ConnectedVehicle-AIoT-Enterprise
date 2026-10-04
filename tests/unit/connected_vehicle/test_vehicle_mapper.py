from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.vehicle import (
    VIN,
    Vehicle,
    VehicleId,
    VehicleStatus,
)
from connected_vehicle.vehicle.persistence.mapper import (
    apply_vehicle_to_model,
    vehicle_from_model,
    vehicle_to_model,
)


def test_vehicle_round_trip_through_model() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vehicle_id=VehicleId("550e8400-e29b-41d4-a716-446655440000"),
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    ).transition_to(
        VehicleStatus.ACTIVE,
        now=now + timedelta(seconds=1),
    )

    model = vehicle_to_model(vehicle)
    restored = vehicle_from_model(model)

    assert restored == vehicle


def test_apply_vehicle_to_existing_model() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vehicle_id=VehicleId("550e8400-e29b-41d4-a716-446655440000"),
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    model = vehicle_to_model(vehicle)

    active = vehicle.transition_to(
        VehicleStatus.ACTIVE,
        now=now + timedelta(seconds=1),
    )

    apply_vehicle_to_model(
        model,
        active,
    )

    assert model.status == VehicleStatus.ACTIVE.value
    assert model.updated_at == active.updated_at


def test_apply_vehicle_rejects_different_id() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    first = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    second = Vehicle.create(
        vin=VIN("2HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    model = vehicle_to_model(first)

    with pytest.raises(ValueError):
        apply_vehicle_to_model(
            model,
            second,
        )
