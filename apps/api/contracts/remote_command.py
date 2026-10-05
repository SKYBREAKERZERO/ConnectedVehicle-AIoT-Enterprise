from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RemoteCommandTypeContract(StrEnum):
    """Public HTTP command-type contract."""

    LOCK = "lock"
    UNLOCK = "unlock"
    START = "start"
    STOP = "stop"
    HONK = "honk"
    FLASH_LIGHTS = "flash_lights"


class RemoteCommandStatusContract(StrEnum):
    """Public HTTP remote-command status contract."""

    REQUESTED = "requested"
    QUEUED = "queued"
    DISPATCHING = "dispatching"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class IssueRemoteCommandRequest(BaseModel):
    """POST remote-command request contract."""

    model_config = ConfigDict(
        extra="forbid",
    )

    command_type: RemoteCommandTypeContract


class IssueRemoteCommandResponse(BaseModel):
    """202 Accepted remote-command response contract."""

    model_config = ConfigDict(
        extra="forbid",
    )

    command_id: UUID
    vehicle_id: UUID
    command_type: RemoteCommandTypeContract
    status: RemoteCommandStatusContract
    created: bool
    created_at: datetime
    expires_at: datetime
