from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from apps.api.contracts.remote_command import (
    IssueRemoteCommandRequest,
    IssueRemoteCommandResponse,
    RemoteCommandStatusContract,
    RemoteCommandTypeContract,
)


def test_remote_command_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        IssueRemoteCommandRequest.model_validate(
            {
                "command_type": "lock",
                "ttl_seconds": 120,
            }
        )


def test_remote_command_public_enum_contract_is_stable() -> None:
    assert [item.value for item in RemoteCommandTypeContract] == [
        "lock",
        "unlock",
        "start",
        "stop",
        "honk",
        "flash_lights",
    ]

    assert [item.value for item in RemoteCommandStatusContract] == [
        "requested",
        "queued",
        "dispatching",
        "sent",
        "acknowledged",
        "succeeded",
        "failed",
        "timed_out",
        "expired",
        "cancelled",
    ]


def test_remote_command_response_serializes_public_contract() -> None:
    response = IssueRemoteCommandResponse(
        command_id=UUID("11111111-1111-4111-8111-111111111111"),
        vehicle_id=UUID("22222222-2222-4222-8222-222222222222"),
        command_type=RemoteCommandTypeContract.LOCK,
        status=RemoteCommandStatusContract.REQUESTED,
        created=True,
        created_at=datetime(
            2026,
            10,
            4,
            12,
            0,
            tzinfo=UTC,
        ),
        expires_at=datetime(
            2026,
            10,
            4,
            12,
            1,
            tzinfo=UTC,
        ),
    )

    payload = response.model_dump(
        mode="json",
    )

    assert payload["command_type"] == "lock"
    assert payload["status"] == "requested"
    assert payload["created"] is True
