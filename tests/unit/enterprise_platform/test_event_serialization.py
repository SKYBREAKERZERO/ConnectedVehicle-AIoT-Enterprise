from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.serialization import (
    EventSerializationError,
    deserialize_event_envelope,
    serialize_event_envelope,
)


def test_event_serialization_round_trip() -> None:
    occurred_at = datetime(
        2026,
        10,
        3,
        2,
        30,
        tzinfo=UTC,
    )

    original = create_event_envelope(
        event_id="event-001",
        event_type="vehicle.command.requested",
        schema_version="1.0",
        source="vehicle-api",
        occurred_at=occurred_at,
        correlation_id="correlation-001",
        trace_id="trace-001",
        payload={
            "vehicle_id": "VIN001",
            "command": "unlock",
            "retryable": False,
        },
    )

    serialized = serialize_event_envelope(original)

    restored = deserialize_event_envelope(serialized)

    assert restored == original


def test_serialized_event_contains_expected_contract() -> None:
    event = create_event_envelope(
        event_id="event-002",
        event_type="vehicle.registered",
        source="vehicle-service",
        correlation_id="correlation-002",
        trace_id=None,
        occurred_at=datetime(
            2026,
            10,
            3,
            3,
            0,
            tzinfo=UTC,
        ),
        payload={
            "vehicle_id": "VIN002",
        },
    )

    raw = json.loads(serialize_event_envelope(event))

    assert raw == {
        "event_id": "event-002",
        "event_type": "vehicle.registered",
        "schema_version": "1.0",
        "source": "vehicle-service",
        "occurred_at": ("2026-10-03T03:00:00+00:00"),
        "correlation_id": "correlation-002",
        "trace_id": None,
        "payload": {
            "vehicle_id": "VIN002",
        },
    }


def test_serialization_rejects_non_json_payload() -> None:
    event = create_event_envelope(
        event_type="vehicle.test",
        source="test-service",
        payload={
            "unsupported": object(),
        },
    )

    with pytest.raises(EventSerializationError):
        serialize_event_envelope(event)


@pytest.mark.parametrize(
    "value",
    [
        "not-json",
        "[]",
        "{}",
    ],
)
def test_deserialization_rejects_invalid_envelope(
    value: str,
) -> None:
    with pytest.raises(EventSerializationError):
        deserialize_event_envelope(value)


def test_deserialization_rejects_naive_timestamp() -> None:
    value = json.dumps(
        {
            "event_id": "event-003",
            "event_type": "vehicle.registered",
            "schema_version": "1.0",
            "source": "vehicle-service",
            "occurred_at": "2026-10-03T03:00:00",
            "correlation_id": None,
            "trace_id": None,
            "payload": {},
        }
    )

    with pytest.raises(
        EventSerializationError,
        match="timezone-aware",
    ):
        deserialize_event_envelope(value)


def test_deserialization_rejects_non_object_payload() -> None:
    value = json.dumps(
        {
            "event_id": "event-004",
            "event_type": "vehicle.registered",
            "schema_version": "1.0",
            "source": "vehicle-service",
            "occurred_at": ("2026-10-03T03:00:00+00:00"),
            "correlation_id": None,
            "trace_id": None,
            "payload": [],
        }
    )

    with pytest.raises(
        EventSerializationError,
        match="payload",
    ):
        deserialize_event_envelope(value)
