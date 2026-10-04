from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from connected_vehicle.vehicle.exceptions import (
    InvalidTenantIdError,
    InvalidVehicleIdError,
    InvalidVehicleTransitionError,
    InvalidVINError,
)

_VIN_PATTERN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")


@dataclass(frozen=True, slots=True)
class VIN:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().upper()

        if not _VIN_PATTERN.fullmatch(normalized):
            raise InvalidVINError(
                "VIN must contain exactly 17 uppercase "
                "letters/digits and must not contain I, O, or Q."
            )

        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class VehicleId:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip()

        try:
            parsed = UUID(normalized)
        except ValueError as exc:
            raise InvalidVehicleIdError("Vehicle ID must be a valid UUID.") from exc

        object.__setattr__(self, "value", str(parsed))

    @classmethod
    def new(cls) -> VehicleId:
        return cls(str(uuid4()))

    def __str__(self) -> str:
        return self.value


class VehicleStatus(StrEnum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


_ALLOWED_TRANSITIONS: dict[
    VehicleStatus,
    frozenset[VehicleStatus],
] = {
    VehicleStatus.PROVISIONING: frozenset(
        {
            VehicleStatus.ACTIVE,
            VehicleStatus.DECOMMISSIONED,
        }
    ),
    VehicleStatus.ACTIVE: frozenset(
        {
            VehicleStatus.SUSPENDED,
            VehicleStatus.DECOMMISSIONED,
        }
    ),
    VehicleStatus.SUSPENDED: frozenset(
        {
            VehicleStatus.ACTIVE,
            VehicleStatus.DECOMMISSIONED,
        }
    ),
    VehicleStatus.DECOMMISSIONED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class Vehicle:
    id: VehicleId
    vin: VIN
    tenant_id: str
    status: VehicleStatus
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        tenant_id = self.tenant_id.strip()

        if not tenant_id:
            raise InvalidTenantIdError("Vehicle tenant ID must not be empty.")

        if self.created_at.tzinfo is None:
            raise ValueError("Vehicle created_at must be timezone-aware.")

        if self.updated_at.tzinfo is None:
            raise ValueError("Vehicle updated_at must be timezone-aware.")

        if self.updated_at < self.created_at:
            raise ValueError("Vehicle updated_at must not be earlier than created_at.")

        object.__setattr__(self, "tenant_id", tenant_id)

    @classmethod
    def create(
        cls,
        *,
        vin: VIN,
        tenant_id: str,
        vehicle_id: VehicleId | None = None,
        now: datetime | None = None,
    ) -> Vehicle:
        timestamp = now if now is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Vehicle creation time must be timezone-aware.")

        return cls(
            id=vehicle_id if vehicle_id is not None else VehicleId.new(),
            vin=vin,
            tenant_id=tenant_id,
            status=VehicleStatus.PROVISIONING,
            created_at=timestamp,
            updated_at=timestamp,
        )

    def transition_to(
        self,
        status: VehicleStatus,
        *,
        now: datetime | None = None,
    ) -> Vehicle:
        if status is self.status:
            return self

        if status not in _ALLOWED_TRANSITIONS[self.status]:
            raise InvalidVehicleTransitionError(
                "Vehicle status transition "
                f"{self.status.value!r} -> {status.value!r} "
                "is not allowed."
            )

        timestamp = now if now is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Vehicle transition time must be timezone-aware.")

        if timestamp < self.updated_at:
            raise ValueError("Vehicle transition time must not be earlier than current updated_at.")

        return Vehicle(
            id=self.id,
            vin=self.vin,
            tenant_id=self.tenant_id,
            status=status,
            created_at=self.created_at,
            updated_at=timestamp,
        )

    @property
    def accepts_remote_commands(self) -> bool:
        return self.status is VehicleStatus.ACTIVE
