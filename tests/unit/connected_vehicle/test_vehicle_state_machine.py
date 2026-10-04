from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.vehicle import (
    VIN,
    InvalidTenantIdError,
    InvalidVehicleTransitionError,
    Vehicle,
    VehicleStatus,
)


def test_vehicle_starts_in_provisioning_state() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    assert vehicle.status is VehicleStatus.PROVISIONING
    assert vehicle.created_at == now
    assert vehicle.updated_at == now
    assert vehicle.accepts_remote_commands is False


def test_vehicle_can_be_activated() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    active = vehicle.transition_to(
        VehicleStatus.ACTIVE,
        now=now + timedelta(seconds=1),
    )

    assert active.status is VehicleStatus.ACTIVE
    assert active.accepts_remote_commands is True


def test_active_vehicle_can_be_suspended_and_reactivated() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    active = vehicle.transition_to(
        VehicleStatus.ACTIVE,
        now=now + timedelta(seconds=1),
    )
    suspended = active.transition_to(
        VehicleStatus.SUSPENDED,
        now=now + timedelta(seconds=2),
    )
    reactivated = suspended.transition_to(
        VehicleStatus.ACTIVE,
        now=now + timedelta(seconds=3),
    )

    assert suspended.accepts_remote_commands is False
    assert reactivated.accepts_remote_commands is True


def test_decommissioned_vehicle_is_terminal() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    decommissioned = vehicle.transition_to(
        VehicleStatus.DECOMMISSIONED,
        now=now + timedelta(seconds=1),
    )

    with pytest.raises(InvalidVehicleTransitionError):
        decommissioned.transition_to(
            VehicleStatus.ACTIVE,
            now=now + timedelta(seconds=2),
        )


def test_vehicle_rejects_backward_transition_time() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    vehicle = Vehicle.create(
        vin=VIN("1HGCM82633A004352"),
        tenant_id="tenant-001",
        now=now,
    )

    with pytest.raises(ValueError):
        vehicle.transition_to(
            VehicleStatus.ACTIVE,
            now=now - timedelta(seconds=1),
        )


def test_vehicle_rejects_empty_tenant_id() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    with pytest.raises(InvalidTenantIdError):
        Vehicle.create(
            vin=VIN("1HGCM82633A004352"),
            tenant_id="   ",
            now=now,
        )
