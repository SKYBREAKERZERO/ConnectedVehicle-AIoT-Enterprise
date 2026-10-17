"""Version 2 execution protocol; Day17 contracts remain frozen."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from connected_vehicle.ota.contracts import Contract, ECUView, FirmwareRegistration, Name


class OTAState(StrEnum):
    PENDING = "pending_verification"
    VERIFIED = "verified"
    DOWNLOADING = "downloading"
    INSTALLING = "installing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_STATES = ("pending_verification", "verified", "downloading", "installing")


class VerificationRequest(Contract):
    operation_id: UUID
    key_id: Name
    security_version: int = Field(strict=True, ge=1, le=9223372036854775807)
    signature: str = Field(min_length=88, max_length=88)

    @field_validator("signature")
    @classmethod
    def ed25519_signature(cls, value: str) -> str:
        try:
            signature = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("Invalid signature encoding") from exc
        if len(signature) != 64 or base64.b64encode(signature).decode() != value:
            raise ValueError("Expected canonical Ed25519 signature")
        return value


class SignedManifest(FirmwareRegistration):
    protocol: Literal["cv-ota/2"] = "cv-ota/2"
    tenant_id: str = Field(min_length=1, max_length=255)
    release_id: UUID
    security_version: int = Field(strict=True, ge=1, le=9223372036854775807)
    key_id: Name

    def canonical(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()


class ExecutionView(Contract):
    id: UUID
    vehicle_id: UUID
    ecu_id: UUID
    release_id: UUID
    status: OTAState
    created_at: datetime
    updated_at: datetime
    created_by: str


class ExecutionECUView(ECUView):
    security_version: int = Field(ge=0)


class ClaimRequest(Contract):
    operation_id: UUID


class ClaimResult(Contract):
    job: ExecutionView
    device_id: str
    claim_token: UUID
    manifest: SignedManifest
    signature: str


class OTAReport(Contract):
    event_id: UUID
    claim_token: UUID
    sequence: int = Field(strict=True, ge=1, le=2)
    status: Literal["installing", "succeeded", "failed"]
    occurred_at: AwareDatetime
    observed_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_code: Literal["download_failed", "integrity_failed", "health_failed"] | None = None
