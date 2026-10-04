from __future__ import annotations

import pytest

from connected_vehicle.vehicle.domain import VIN
from connected_vehicle.vehicle.exceptions import InvalidVINError


def test_vin_normalizes_to_uppercase() -> None:
    vin = VIN("1hgcm82633a004352")

    assert vin.value == "1HGCM82633A004352"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "123",
        "1HGCM82633A00435",
        "1HGCM82633A0043522",
        "1HGCM82633I004352",
        "1HGCM82633O004352",
        "1HGCM82633Q004352",
        "1HGCM82633@004352",
    ],
)
def test_vin_rejects_invalid_values(
    value: str,
) -> None:
    with pytest.raises(InvalidVINError):
        VIN(value)


def test_vehicle_id_normalizes_uuid() -> None:
    from connected_vehicle.vehicle.domain import VehicleId

    vehicle_id = VehicleId("550E8400-E29B-41D4-A716-446655440000")

    assert vehicle_id.value == "550e8400-e29b-41d4-a716-446655440000"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-uuid",
        "550e8400-e29b-41d4-a716-44665544000",
    ],
)
def test_vehicle_id_rejects_invalid_uuid(
    value: str,
) -> None:
    from connected_vehicle.vehicle.domain import VehicleId
    from connected_vehicle.vehicle.exceptions import (
        InvalidVehicleIdError,
    )

    with pytest.raises(InvalidVehicleIdError):
        VehicleId(value)


def test_vehicle_id_new_creates_distinct_ids() -> None:
    from connected_vehicle.vehicle.domain import VehicleId

    first = VehicleId.new()
    second = VehicleId.new()

    assert first != second
