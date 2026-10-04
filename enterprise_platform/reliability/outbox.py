from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)


class OutboxStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    PUBLISHED = "published"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class PendingOutboxEvent:
    """Transport-independent event waiting for reliable publication."""

    event_id: str
    event_type: str
    destination: str
    event_body: str
    created_at: datetime
    available_at: datetime

    @classmethod
    def from_event(
        cls,
        event: EventEnvelope,
        *,
        destination: str,
        created_at: datetime | None = None,
        available_at: datetime | None = None,
    ) -> PendingOutboxEvent:
        normalized_destination = destination.strip()

        if not normalized_destination:
            raise ValueError("Outbox destination must not be empty.")

        resolved_created_at = created_at if created_at is not None else datetime.now(UTC)

        resolved_available_at = available_at if available_at is not None else resolved_created_at

        if resolved_created_at.tzinfo is None:
            raise ValueError("Outbox created_at must be timezone-aware.")

        if resolved_available_at.tzinfo is None:
            raise ValueError("Outbox available_at must be timezone-aware.")

        return cls(
            event_id=event.event_id,
            event_type=event.event_type,
            destination=normalized_destination,
            event_body=serialize_event_envelope(event),
            created_at=resolved_created_at,
            available_at=resolved_available_at,
        )


@dataclass(frozen=True, slots=True)
class ClaimedOutboxEvent:
    """Outbox event leased to a dispatcher worker."""

    id: str
    event_id: str
    event_type: str
    destination: str
    event_body: str
    attempts: int
    claim_token: str
    lease_expires_at: datetime
