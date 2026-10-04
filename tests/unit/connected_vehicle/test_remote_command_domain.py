from __future__ import annotations

import pytest

from connected_vehicle.remote_command import (
    InvalidRemoteCommandIdError,
    RemoteCommandId,
    RemoteCommandType,
)


def test_remote_command_id_normalizes_uuid() -> None:
    command_id = RemoteCommandId("550E8400-E29B-41D4-A716-446655440000")

    assert command_id.value == "550e8400-e29b-41d4-a716-446655440000"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-uuid",
        "550e8400-e29b-41d4-a716-44665544000",
    ],
)
def test_remote_command_id_rejects_invalid_uuid(
    value: str,
) -> None:
    with pytest.raises(InvalidRemoteCommandIdError):
        RemoteCommandId(value)


def test_remote_command_id_new_creates_distinct_ids() -> None:
    first = RemoteCommandId.new()
    second = RemoteCommandId.new()

    assert first != second


def test_remote_command_types_are_stable_wire_values() -> None:
    assert RemoteCommandType.LOCK.value == "lock"
    assert RemoteCommandType.UNLOCK.value == "unlock"
    assert RemoteCommandType.START.value == "start"
    assert RemoteCommandType.STOP.value == "stop"
    assert RemoteCommandType.HONK.value == "honk"
    assert RemoteCommandType.FLASH_LIGHTS.value == "flash_lights"
