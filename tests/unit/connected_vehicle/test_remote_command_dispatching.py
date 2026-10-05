from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from connected_vehicle.remote_command import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.dispatching import (
    RemoteCommandDispatchAction,
    decide_remote_command_dispatch_action,
)
from connected_vehicle.vehicle import VehicleId

DECISION_TIME = datetime(
    2030,
    1,
    1,
    12,
    0,
    tzinfo=UTC,
)


def create_command(
    status: RemoteCommandStatus,
    *,
    expired: bool = False,
) -> RemoteCommand:
    created_at = DECISION_TIME - timedelta(minutes=5)

    expires_at = (
        DECISION_TIME - timedelta(seconds=1) if expired else DECISION_TIME + timedelta(minutes=5)
    )

    return RemoteCommand(
        id=RemoteCommandId.new(),
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-dispatch",
        command_type=RemoteCommandType.LOCK,
        status=status,
        idempotency_key="dispatch-decision",
        created_at=created_at,
        updated_at=created_at,
        expires_at=expires_at,
    )


@pytest.mark.parametrize(
    ("status", "expected_action"),
    [
        (
            RemoteCommandStatus.REQUESTED,
            RemoteCommandDispatchAction.QUEUE,
        ),
        (
            RemoteCommandStatus.QUEUED,
            RemoteCommandDispatchAction.START_DISPATCH,
        ),
        (
            RemoteCommandStatus.DISPATCHING,
            RemoteCommandDispatchAction.PUBLISH,
        ),
    ],
)
def test_dispatch_action_for_active_pre_publish_states(
    status: RemoteCommandStatus,
    expected_action: RemoteCommandDispatchAction,
) -> None:
    command = create_command(status)

    assert (
        decide_remote_command_dispatch_action(
            command,
            now=DECISION_TIME,
        )
        is expected_action
    )


@pytest.mark.parametrize(
    "status",
    [
        RemoteCommandStatus.REQUESTED,
        RemoteCommandStatus.QUEUED,
        RemoteCommandStatus.DISPATCHING,
    ],
)
def test_expired_pre_publish_command_is_expired(
    status: RemoteCommandStatus,
) -> None:
    command = create_command(
        status,
        expired=True,
    )

    assert (
        decide_remote_command_dispatch_action(
            command,
            now=DECISION_TIME,
        )
        is RemoteCommandDispatchAction.EXPIRE
    )


@pytest.mark.parametrize(
    "status",
    [
        RemoteCommandStatus.SENT,
        RemoteCommandStatus.ACKNOWLEDGED,
        RemoteCommandStatus.SUCCEEDED,
        RemoteCommandStatus.FAILED,
        RemoteCommandStatus.TIMED_OUT,
        RemoteCommandStatus.EXPIRED,
        RemoteCommandStatus.CANCELLED,
    ],
)
def test_post_publish_or_terminal_command_acknowledges_duplicate_message(
    status: RemoteCommandStatus,
) -> None:
    command = create_command(
        status,
        expired=True,
    )

    assert (
        decide_remote_command_dispatch_action(
            command,
            now=DECISION_TIME,
        )
        is RemoteCommandDispatchAction.ACKNOWLEDGE
    )


def test_dispatching_command_is_republished_after_redelivery() -> None:
    command = create_command(RemoteCommandStatus.DISPATCHING)

    assert (
        decide_remote_command_dispatch_action(
            command,
            now=DECISION_TIME,
        )
        is RemoteCommandDispatchAction.PUBLISH
    )


def test_dispatch_decision_rejects_naive_time() -> None:
    command = create_command(RemoteCommandStatus.REQUESTED)

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        decide_remote_command_dispatch_action(
            command,
            now=datetime(
                2030,
                1,
                1,
                12,
                0,
            ),
        )
