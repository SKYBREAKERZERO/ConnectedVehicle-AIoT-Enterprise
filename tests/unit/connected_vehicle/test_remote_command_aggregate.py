from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.remote_command import (
    InvalidIdempotencyKeyError,
    InvalidRemoteCommandTTLError,
    RemoteCommand,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.vehicle import VehicleId


def test_remote_command_request_creates_requested_command() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="request-001",
        ttl_seconds=60,
        now=now,
    )

    assert command.status is RemoteCommandStatus.REQUESTED
    assert command.command_type is RemoteCommandType.LOCK
    assert command.tenant_id == "tenant-001"
    assert command.idempotency_key == "request-001"
    assert command.created_at == now
    assert command.updated_at == now
    assert command.expires_at == now + timedelta(seconds=60)
    assert command.is_terminal is False


def test_remote_command_transition_preserves_identity() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.UNLOCK,
        idempotency_key="request-002",
        now=now,
    )

    queued = command.transition_to(
        RemoteCommandStatus.QUEUED,
        now=now + timedelta(seconds=1),
    )

    assert queued.id == command.id
    assert queued.vehicle_id == command.vehicle_id
    assert queued.idempotency_key == command.idempotency_key
    assert queued.status is RemoteCommandStatus.QUEUED
    assert queued.updated_at == now + timedelta(seconds=1)


def test_remote_command_expiration_boundary() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.HONK,
        idempotency_key="request-003",
        ttl_seconds=30,
        now=now,
    )

    assert (
        command.is_expired(
            at=now + timedelta(seconds=29),
        )
        is False
    )
    assert (
        command.is_expired(
            at=now + timedelta(seconds=30),
        )
        is True
    )


@pytest.mark.parametrize(
    "ttl_seconds",
    [
        0,
        -1,
        301,
    ],
)
def test_remote_command_rejects_invalid_ttl(
    ttl_seconds: int,
) -> None:
    with pytest.raises(InvalidRemoteCommandTTLError):
        RemoteCommand.request(
            vehicle_id=VehicleId.new(),
            tenant_id="tenant-001",
            command_type=RemoteCommandType.START,
            idempotency_key="request-004",
            ttl_seconds=ttl_seconds,
        )


@pytest.mark.parametrize(
    "idempotency_key",
    [
        "",
        "   ",
        "x" * 256,
    ],
)
def test_remote_command_rejects_invalid_idempotency_key(
    idempotency_key: str,
) -> None:
    with pytest.raises(InvalidIdempotencyKeyError):
        RemoteCommand.request(
            vehicle_id=VehicleId.new(),
            tenant_id="tenant-001",
            command_type=RemoteCommandType.STOP,
            idempotency_key=idempotency_key,
        )


def test_remote_command_rejects_backward_transition_time() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.FLASH_LIGHTS,
        idempotency_key="request-005",
        now=now,
    )

    with pytest.raises(ValueError):
        command.transition_to(
            RemoteCommandStatus.QUEUED,
            now=now - timedelta(seconds=1),
        )


def test_remote_command_terminal_property() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="request-006",
        now=now,
    )

    failed = command.transition_to(
        RemoteCommandStatus.FAILED,
        now=now + timedelta(seconds=1),
    )

    assert failed.is_terminal is True
