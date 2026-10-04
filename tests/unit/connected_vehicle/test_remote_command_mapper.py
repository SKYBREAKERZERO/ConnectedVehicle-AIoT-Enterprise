from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.remote_command import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.persistence.mapper import (
    apply_remote_command_to_model,
    remote_command_from_model,
    remote_command_to_model,
)
from connected_vehicle.vehicle import VehicleId


def create_command(
    *,
    command_id: RemoteCommandId | None = None,
    vehicle_id: VehicleId | None = None,
) -> RemoteCommand:
    return RemoteCommand.request(
        command_id=command_id,
        vehicle_id=(vehicle_id if vehicle_id is not None else VehicleId.new()),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="request-001",
        now=datetime(2030, 1, 1, tzinfo=UTC),
    )


def test_remote_command_round_trip_through_model() -> None:
    command = create_command().transition_to(
        RemoteCommandStatus.QUEUED,
        now=datetime(2030, 1, 1, tzinfo=UTC) + timedelta(seconds=1),
    )

    model = remote_command_to_model(command)
    restored = remote_command_from_model(model)

    assert restored == command


def test_apply_remote_command_updates_existing_model() -> None:
    command = create_command()
    model = remote_command_to_model(command)

    queued = command.transition_to(
        RemoteCommandStatus.QUEUED,
        now=command.created_at + timedelta(seconds=1),
    )

    apply_remote_command_to_model(
        model,
        queued,
    )

    assert model.status == RemoteCommandStatus.QUEUED.value
    assert model.updated_at == queued.updated_at
    assert model.expires_at == queued.expires_at


def test_apply_remote_command_rejects_different_command_id() -> None:
    first = create_command()
    second = create_command()

    model = remote_command_to_model(first)

    with pytest.raises(
        ValueError,
        match="different ID",
    ):
        apply_remote_command_to_model(
            model,
            second,
        )


def test_apply_remote_command_rejects_different_vehicle_id() -> None:
    command = create_command()
    model = remote_command_to_model(command)

    other_vehicle_command = create_command(
        command_id=command.id,
        vehicle_id=VehicleId.new(),
    )

    with pytest.raises(
        ValueError,
        match="Cannot change the vehicle",
    ):
        apply_remote_command_to_model(
            model,
            other_vehicle_command,
        )
