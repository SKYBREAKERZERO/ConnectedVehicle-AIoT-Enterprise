from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Name = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    ),
]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ECURegistration(Contract):
    ecu_type: Name
    hardware_version: Name
    firmware_version: Name
    serial_number: Name


class ECUView(ECURegistration):
    id: UUID
    vehicle_id: UUID
    created_at: datetime
    created_by: str


class FirmwareRegistration(Contract):
    ecu_type: Name
    hardware_version: Name
    version: Name
    artifact_bucket: str = Field(
        min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$"
    )
    artifact_key: str = Field(min_length=1, max_length=1024)
    artifact_version: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(strict=True, gt=0, le=4 * 1024**3)

    @field_validator("artifact_key", "artifact_version")
    @classmethod
    def pinned_reference(cls, value: str) -> str:
        if value != value.strip() or any(ord(c) < 32 for c in value) or value == "null":
            raise ValueError("A concrete object key and immutable version are required")
        return value


class FirmwareView(FirmwareRegistration):
    id: UUID
    created_at: datetime
    created_by: str
    verification_status: Literal["unverified"] = "unverified"


class JobRequest(Contract):
    release_id: UUID


class JobView(Contract):
    id: UUID
    vehicle_id: UUID
    ecu_id: UUID
    release_id: UUID
    status: Literal["pending_verification", "cancelled"]
    created_at: datetime
    updated_at: datetime
    created_by: str


class CancelJob(Contract):
    reason: Reason


class ECUResult(Contract):
    created: bool
    ecu: ECUView


class FirmwareResult(Contract):
    created: bool
    release: FirmwareView


class JobResult(Contract):
    created: bool
    job: JobView
