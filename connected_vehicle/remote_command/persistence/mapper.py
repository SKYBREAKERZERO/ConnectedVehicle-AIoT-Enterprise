from __future__ import annotations

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.vehicle import VehicleId


def remote_command_to_model(
    command: RemoteCommand,
) -> RemoteCommandModel:
    return RemoteCommandModel(
        id=command.id.value,
        vehicle_id=command.vehicle_id.value,
        tenant_id=command.tenant_id,
        command_type=command.command_type.value,
        status=command.status.value,
        idempotency_key=command.idempotency_key,
        created_at=command.created_at,
        updated_at=command.updated_at,
        expires_at=command.expires_at,
    )


def remote_command_from_model(
    model: RemoteCommandModel,
) -> RemoteCommand:
    return RemoteCommand(
        id=RemoteCommandId(model.id),
        vehicle_id=VehicleId(model.vehicle_id),
        tenant_id=model.tenant_id,
        command_type=RemoteCommandType(model.command_type),
        status=RemoteCommandStatus(model.status),
        idempotency_key=model.idempotency_key,
        created_at=model.created_at,
        updated_at=model.updated_at,
        expires_at=model.expires_at,
    )


def apply_remote_command_to_model(
    model: RemoteCommandModel,
    command: RemoteCommand,
) -> None:
    if model.id != command.id.value:
        raise ValueError("Cannot apply a RemoteCommand to a model with a different ID.")

    if model.vehicle_id != command.vehicle_id.value:
        raise ValueError("Cannot change the vehicle associated with an existing RemoteCommand.")

    model.tenant_id = command.tenant_id
    model.command_type = command.command_type.value
    model.status = command.status.value
    model.idempotency_key = command.idempotency_key
    model.created_at = command.created_at
    model.updated_at = command.updated_at
    model.expires_at = command.expires_at
