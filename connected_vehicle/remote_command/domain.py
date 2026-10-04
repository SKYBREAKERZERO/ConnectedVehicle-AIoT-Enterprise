from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from connected_vehicle.remote_command.exceptions import (
    InvalidIdempotencyKeyError,
    InvalidRemoteCommandIdError,
    InvalidRemoteCommandTransitionError,
    InvalidRemoteCommandTTLError,
)
from connected_vehicle.vehicle import VehicleId

DEFAULT_REMOTE_COMMAND_TTL_SECONDS = 60
MAX_REMOTE_COMMAND_TTL_SECONDS = 300


@dataclass(frozen=True, slots=True)
class RemoteCommandId:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip()

        try:
            parsed = UUID(normalized)
        except ValueError as exc:
            raise InvalidRemoteCommandIdError("Remote command ID must be a valid UUID.") from exc

        object.__setattr__(
            self,
            "value",
            str(parsed),
        )

    @classmethod
    def new(cls) -> RemoteCommandId:
        return cls(str(uuid4()))

    def __str__(self) -> str:
        return self.value


class RemoteCommandType(StrEnum):
    LOCK = "lock"
    UNLOCK = "unlock"
    START = "start"
    STOP = "stop"
    HONK = "honk"
    FLASH_LIGHTS = "flash_lights"


class RemoteCommandStatus(StrEnum):
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


_TERMINAL_STATUSES = frozenset(
    {
        RemoteCommandStatus.SUCCEEDED,
        RemoteCommandStatus.FAILED,
        RemoteCommandStatus.TIMED_OUT,
        RemoteCommandStatus.EXPIRED,
        RemoteCommandStatus.CANCELLED,
    }
)


_ALLOWED_STATUS_TRANSITIONS: dict[
    RemoteCommandStatus,
    frozenset[RemoteCommandStatus],
] = {
    RemoteCommandStatus.REQUESTED: frozenset(
        {
            RemoteCommandStatus.QUEUED,
            RemoteCommandStatus.FAILED,
            RemoteCommandStatus.EXPIRED,
            RemoteCommandStatus.CANCELLED,
        }
    ),
    RemoteCommandStatus.QUEUED: frozenset(
        {
            RemoteCommandStatus.DISPATCHING,
            RemoteCommandStatus.FAILED,
            RemoteCommandStatus.EXPIRED,
            RemoteCommandStatus.CANCELLED,
        }
    ),
    RemoteCommandStatus.DISPATCHING: frozenset(
        {
            RemoteCommandStatus.SENT,
            RemoteCommandStatus.FAILED,
            RemoteCommandStatus.TIMED_OUT,
            RemoteCommandStatus.EXPIRED,
        }
    ),
    RemoteCommandStatus.SENT: frozenset(
        {
            RemoteCommandStatus.ACKNOWLEDGED,
            RemoteCommandStatus.FAILED,
            RemoteCommandStatus.TIMED_OUT,
        }
    ),
    RemoteCommandStatus.ACKNOWLEDGED: frozenset(
        {
            RemoteCommandStatus.SUCCEEDED,
            RemoteCommandStatus.FAILED,
            RemoteCommandStatus.TIMED_OUT,
        }
    ),
    RemoteCommandStatus.SUCCEEDED: frozenset(),
    RemoteCommandStatus.FAILED: frozenset(),
    RemoteCommandStatus.TIMED_OUT: frozenset(),
    RemoteCommandStatus.EXPIRED: frozenset(),
    RemoteCommandStatus.CANCELLED: frozenset(),
}


def is_terminal_status(
    status: RemoteCommandStatus,
) -> bool:
    return status in _TERMINAL_STATUSES


def can_transition_status(
    current: RemoteCommandStatus,
    target: RemoteCommandStatus,
) -> bool:
    if target is current:
        return True

    return target in _ALLOWED_STATUS_TRANSITIONS[current]


def ensure_status_transition(
    current: RemoteCommandStatus,
    target: RemoteCommandStatus,
) -> None:
    if can_transition_status(current, target):
        return

    raise InvalidRemoteCommandTransitionError(
        f"Remote command status transition {current.value!r} -> {target.value!r} is not allowed."
    )


@dataclass(frozen=True, slots=True)
class RemoteCommand:
    id: RemoteCommandId
    vehicle_id: VehicleId
    tenant_id: str
    command_type: RemoteCommandType
    status: RemoteCommandStatus
    idempotency_key: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        tenant_id = self.tenant_id.strip()
        idempotency_key = self.idempotency_key.strip()

        if not tenant_id:
            raise ValueError("Remote command tenant ID must not be empty.")

        if not idempotency_key:
            raise InvalidIdempotencyKeyError("Remote command idempotency key must not be empty.")

        if len(idempotency_key) > 255:
            raise InvalidIdempotencyKeyError(
                "Remote command idempotency key must not exceed 255 characters."
            )

        for name, value in (
            ("created_at", self.created_at),
            ("updated_at", self.updated_at),
            ("expires_at", self.expires_at),
        ):
            if value.tzinfo is None:
                raise ValueError(f"Remote command {name} must be timezone-aware.")

        if self.updated_at < self.created_at:
            raise ValueError("Remote command updated_at must not be earlier than created_at.")

        if self.expires_at <= self.created_at:
            raise ValueError("Remote command expires_at must be later than created_at.")

        object.__setattr__(
            self,
            "tenant_id",
            tenant_id,
        )
        object.__setattr__(
            self,
            "idempotency_key",
            idempotency_key,
        )

    @classmethod
    def request(
        cls,
        *,
        vehicle_id: VehicleId,
        tenant_id: str,
        command_type: RemoteCommandType,
        idempotency_key: str,
        command_id: RemoteCommandId | None = None,
        ttl_seconds: int = DEFAULT_REMOTE_COMMAND_TTL_SECONDS,
        now: datetime | None = None,
    ) -> RemoteCommand:
        if not 1 <= ttl_seconds <= MAX_REMOTE_COMMAND_TTL_SECONDS:
            raise InvalidRemoteCommandTTLError(
                "Remote command TTL must be between 1 and "
                f"{MAX_REMOTE_COMMAND_TTL_SECONDS} seconds."
            )

        timestamp = now if now is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Remote command request time must be timezone-aware.")

        return cls(
            id=command_id if command_id is not None else RemoteCommandId.new(),
            vehicle_id=vehicle_id,
            tenant_id=tenant_id,
            command_type=command_type,
            status=RemoteCommandStatus.REQUESTED,
            idempotency_key=idempotency_key,
            created_at=timestamp,
            updated_at=timestamp,
            expires_at=timestamp + timedelta(seconds=ttl_seconds),
        )

    def transition_to(
        self,
        status: RemoteCommandStatus,
        *,
        now: datetime | None = None,
    ) -> RemoteCommand:
        if status is self.status:
            return self

        ensure_status_transition(
            self.status,
            status,
        )

        timestamp = now if now is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Remote command transition time must be timezone-aware.")

        if timestamp < self.updated_at:
            raise ValueError(
                "Remote command transition time must not be earlier than current updated_at."
            )

        return RemoteCommand(
            id=self.id,
            vehicle_id=self.vehicle_id,
            tenant_id=self.tenant_id,
            command_type=self.command_type,
            status=status,
            idempotency_key=self.idempotency_key,
            created_at=self.created_at,
            updated_at=timestamp,
            expires_at=self.expires_at,
        )

    def is_expired(
        self,
        *,
        at: datetime | None = None,
    ) -> bool:
        timestamp = at if at is not None else datetime.now(UTC)

        if timestamp.tzinfo is None:
            raise ValueError("Remote command expiration check time must be timezone-aware.")

        return timestamp >= self.expires_at

    @property
    def is_terminal(self) -> bool:
        return is_terminal_status(self.status)
