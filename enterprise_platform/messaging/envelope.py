from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from enterprise_platform.observability.context import (
    get_observability_context,
)


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Stable envelope shared by asynchronous platform events."""

    event_id: str
    event_type: str
    schema_version: str
    source: str
    occurred_at: datetime

    correlation_id: str | None
    trace_id: str | None

    payload: Mapping[str, object]


def _normalize_required_value(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{field_name} must not be empty.")

    return normalized


def create_event_envelope(
    *,
    event_type: str,
    source: str,
    payload: Mapping[str, object],
    schema_version: str = "1.0",
    event_id: str | None = None,
    occurred_at: datetime | None = None,
    correlation_id: str | None = None,
    trace_id: str | None = None,
) -> EventEnvelope:
    """Create a normalized event envelope.

    Correlation and trace identifiers default to the current
    observability context but can be supplied explicitly when
    reconstructing or forwarding an event.
    """

    normalized_event_type = _normalize_required_value(
        event_type,
        field_name="Event type",
    )

    normalized_source = _normalize_required_value(
        source,
        field_name="Event source",
    )

    normalized_schema_version = _normalize_required_value(
        schema_version,
        field_name="Schema version",
    )

    normalized_event_id = (
        _normalize_required_value(
            event_id,
            field_name="Event ID",
        )
        if event_id is not None
        else str(uuid4())
    )

    timestamp = occurred_at if occurred_at is not None else datetime.now(UTC)

    if timestamp.tzinfo is None:
        raise ValueError("Event timestamp must be timezone-aware.")

    observability_context = get_observability_context()

    resolved_correlation_id = (
        correlation_id if correlation_id is not None else observability_context.correlation_id
    )

    resolved_trace_id = trace_id if trace_id is not None else observability_context.trace_id

    return EventEnvelope(
        event_id=normalized_event_id,
        event_type=normalized_event_type,
        schema_version=normalized_schema_version,
        source=normalized_source,
        occurred_at=timestamp,
        correlation_id=resolved_correlation_id,
        trace_id=resolved_trace_id,
        payload=dict(payload),
    )
