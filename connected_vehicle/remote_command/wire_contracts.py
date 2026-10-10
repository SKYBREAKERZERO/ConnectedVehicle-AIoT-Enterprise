from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from connected_vehicle.remote_command.domain import RemoteCommandType


class DispatchPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    command_id: UUID
    vehicle_id: UUID
    tenant_id: str = Field(min_length=1, max_length=255)
    command_type: RemoteCommandType
    created_at: AwareDatetime
    expires_at: AwareDatetime


class RequestedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: UUID
    vehicle_id: UUID
    tenant_id: str = Field(min_length=1, max_length=255)
    command_type: RemoteCommandType
    status: Literal["requested"]
    created_at: AwareDatetime
    expires_at: AwareDatetime
