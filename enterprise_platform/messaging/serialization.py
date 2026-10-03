from __future__ import annotations

import json
from datetime import datetime
from typing import Any, cast

from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)


class EventSerializationError(Exception):
    """Raised when an event cannot be serialized or deserialized."""


def serialize_event_envelope(
    event: EventEnvelope,
) -> str:
    payload = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "schema_version": event.schema_version,
        "source": event.source,
        "occurred_at": event.occurred_at.isoformat(),
        "correlation_id": event.correlation_id,
        "trace_id": event.trace_id,
        "payload": dict(event.payload),
    }

    try:
        return json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise EventSerializationError(
            "Event envelope contains a value that cannot be serialized."
        ) from exc


def deserialize_event_envelope(
    value: str,
) -> EventEnvelope:
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as exc:
        raise EventSerializationError("Event envelope is not valid JSON.") from exc

    if not isinstance(raw, dict):
        raise EventSerializationError("Event envelope must be a JSON object.")

    data = cast(dict[str, Any], raw)

    try:
        event_id = data["event_id"]
        event_type = data["event_type"]
        schema_version = data["schema_version"]
        source = data["source"]
        occurred_at_raw = data["occurred_at"]
        correlation_id = data.get("correlation_id")
        trace_id = data.get("trace_id")
        payload = data["payload"]
    except KeyError as exc:
        raise EventSerializationError("Event envelope is missing a required field.") from exc

    if not all(
        isinstance(item, str)
        for item in (
            event_id,
            event_type,
            schema_version,
            source,
            occurred_at_raw,
        )
    ):
        raise EventSerializationError("Event envelope contains an invalid field type.")

    if correlation_id is not None and not isinstance(
        correlation_id,
        str,
    ):
        raise EventSerializationError("Event correlation ID must be a string or null.")

    if trace_id is not None and not isinstance(
        trace_id,
        str,
    ):
        raise EventSerializationError("Event trace ID must be a string or null.")

    if not isinstance(payload, dict):
        raise EventSerializationError("Event payload must be a JSON object.")

    try:
        occurred_at = datetime.fromisoformat(occurred_at_raw)
    except ValueError as exc:
        raise EventSerializationError("Event timestamp is invalid.") from exc

    if occurred_at.tzinfo is None:
        raise EventSerializationError("Event timestamp must be timezone-aware.")

    try:
        return create_event_envelope(
            event_id=event_id,
            event_type=event_type,
            schema_version=schema_version,
            source=source,
            occurred_at=occurred_at,
            correlation_id=correlation_id,
            trace_id=trace_id,
            payload=cast(
                dict[str, object],
                payload,
            ),
        )
    except ValueError as exc:
        raise EventSerializationError("Event envelope contains invalid values.") from exc
