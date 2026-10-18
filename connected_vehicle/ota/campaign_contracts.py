"""Versioned, bounded campaign intents; targets become immutable on freeze."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from connected_vehicle.ota.contracts import Name
from connected_vehicle.ota.execution_contracts import VerificationRequest


class CampaignState(StrEnum):
    DRAFT = "draft"
    FROZEN = "frozen"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*")
    @classmethod
    def no_control_characters(cls, value: object) -> object:
        if isinstance(value, str) and any(ord(c) < 32 for c in value):
            raise ValueError("Control characters are not permitted")
        return value


class CampaignCreate(Contract):
    operation_id: UUID
    name: str = Field(min_length=1, max_length=128)
    release_id: UUID
    security_version: int = Field(strict=True, ge=1, le=9223372036854775807)
    key_id: Name
    signature: str = Field(min_length=88, max_length=88)
    canary_size: int = Field(strict=True, ge=1, le=100)
    wave_size: int = Field(strict=True, ge=1, le=100)
    max_failures: int = Field(strict=True, default=0, ge=0, le=99)
    observation_seconds: int = Field(strict=True, default=30, ge=0, le=3600)
    wave_timeout_seconds: int = Field(strict=True, default=900, ge=30, le=86400)

    @field_validator("signature")
    @classmethod
    def signature_encoding(cls, value: str) -> str:
        return VerificationRequest.ed25519_signature(value)

    @model_validator(mode="after")
    def failure_budget(self) -> CampaignCreate:
        if self.max_failures >= self.canary_size:
            raise ValueError("Canary must require at least one successful installation")
        return self


class CampaignFreeze(Contract):
    operation_id: UUID
    ecu_ids: list[UUID] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_targets(self) -> CampaignFreeze:
        if len(self.ecu_ids) != len(set(self.ecu_ids)):
            raise ValueError("Duplicate ECU target")
        self.ecu_ids.sort(key=str)
        return self


class CampaignAction(Contract):
    operation_id: UUID
    reason: str = Field(min_length=1, max_length=500)


class CampaignView(Contract):
    id: UUID
    name: str
    release_id: UUID
    created_by: str
    canary_size: int
    wave_size: int
    max_failures: int
    observation_seconds: int
    wave_timeout_seconds: int
    publisher_key_id: str
    status: CampaignState
    current_wave: int
    snapshot_sha256: str | None
    target_count: int
    job_count: int
    succeeded: int
    failed: int
    pause_reason: str | None
    created_at: datetime
    updated_at: datetime


class CampaignTarget(Contract):
    ecu_id: UUID
    vehicle_id: UUID
    wave: int
    job_id: UUID
    dispatched: bool
    firmware_version: str
    security_version: int
    job_status: str | None


CampaignList = Annotated[list[CampaignView], Field(max_length=100)]
