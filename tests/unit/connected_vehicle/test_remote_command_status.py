from __future__ import annotations

import pytest

from connected_vehicle.remote_command import (
    InvalidRemoteCommandTransitionError,
    RemoteCommandStatus,
    can_transition_status,
    ensure_status_transition,
    is_terminal_status,
)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (
            RemoteCommandStatus.REQUESTED,
            RemoteCommandStatus.QUEUED,
        ),
        (
            RemoteCommandStatus.QUEUED,
            RemoteCommandStatus.DISPATCHING,
        ),
        (
            RemoteCommandStatus.DISPATCHING,
            RemoteCommandStatus.SENT,
        ),
        (
            RemoteCommandStatus.SENT,
            RemoteCommandStatus.ACKNOWLEDGED,
        ),
        (
            RemoteCommandStatus.ACKNOWLEDGED,
            RemoteCommandStatus.SUCCEEDED,
        ),
    ],
)
def test_happy_path_status_transitions_are_allowed(
    current: RemoteCommandStatus,
    target: RemoteCommandStatus,
) -> None:
    assert can_transition_status(current, target) is True
    ensure_status_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (
            RemoteCommandStatus.REQUESTED,
            RemoteCommandStatus.SENT,
        ),
        (
            RemoteCommandStatus.QUEUED,
            RemoteCommandStatus.SUCCEEDED,
        ),
        (
            RemoteCommandStatus.SENT,
            RemoteCommandStatus.SUCCEEDED,
        ),
        (
            RemoteCommandStatus.ACKNOWLEDGED,
            RemoteCommandStatus.QUEUED,
        ),
    ],
)
def test_invalid_status_transitions_are_rejected(
    current: RemoteCommandStatus,
    target: RemoteCommandStatus,
) -> None:
    assert can_transition_status(current, target) is False

    with pytest.raises(InvalidRemoteCommandTransitionError):
        ensure_status_transition(current, target)


@pytest.mark.parametrize(
    "status",
    [
        RemoteCommandStatus.SUCCEEDED,
        RemoteCommandStatus.FAILED,
        RemoteCommandStatus.TIMED_OUT,
        RemoteCommandStatus.EXPIRED,
        RemoteCommandStatus.CANCELLED,
    ],
)
def test_terminal_statuses_are_terminal(
    status: RemoteCommandStatus,
) -> None:
    assert is_terminal_status(status) is True

    assert (
        can_transition_status(
            status,
            RemoteCommandStatus.QUEUED,
        )
        is False
    )


def test_same_status_is_idempotent() -> None:
    assert (
        can_transition_status(
            RemoteCommandStatus.SENT,
            RemoteCommandStatus.SENT,
        )
        is True
    )

    ensure_status_transition(
        RemoteCommandStatus.SENT,
        RemoteCommandStatus.SENT,
    )
