from __future__ import annotations

from datetime import UTC, datetime

import pytest

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.observability.context import (
    bind_observability_context,
)


def test_create_event_envelope_normalizes_values() -> None:
    event = create_event_envelope(
        event_type=" vehicle.command.requested ",
        source=" vehicle-api ",
        schema_version=" 1.0 ",
        event_id=" event-001 ",
        payload={
            "vehicle_id": "VIN001",
        },
    )

    assert event.event_id == "event-001"
    assert event.event_type == "vehicle.command.requested"
    assert event.source == "vehicle-api"
    assert event.schema_version == "1.0"
    assert event.payload == {
        "vehicle_id": "VIN001",
    }
    assert event.occurred_at.tzinfo is not None


def test_event_envelope_captures_observability_context() -> None:
    with bind_observability_context(
        request_id="request-001",
        correlation_id="correlation-001",
        trace_id="trace-001",
    ):
        event = create_event_envelope(
            event_type="vehicle.command.requested",
            source="vehicle-api",
            payload={},
        )

    assert event.correlation_id == "correlation-001"
    assert event.trace_id == "trace-001"


def test_explicit_trace_context_overrides_current_context() -> None:
    with bind_observability_context(
        request_id="request-002",
        correlation_id="current-correlation",
        trace_id="current-trace",
    ):
        event = create_event_envelope(
            event_type="vehicle.command.requested",
            source="vehicle-api",
            correlation_id="forwarded-correlation",
            trace_id="forwarded-trace",
            payload={},
        )

    assert event.correlation_id == "forwarded-correlation"
    assert event.trace_id == "forwarded-trace"


def test_event_envelope_accepts_explicit_timestamp() -> None:
    occurred_at = datetime(
        2026,
        10,
        3,
        2,
        0,
        tzinfo=UTC,
    )

    event = create_event_envelope(
        event_type="vehicle.registered",
        source="vehicle-service",
        occurred_at=occurred_at,
        payload={},
    )

    assert event.occurred_at == occurred_at


@pytest.mark.parametrize(
    ("field_name", "kwargs"),
    [
        (
            "Event type",
            {
                "event_type": "   ",
                "source": "vehicle-api",
            },
        ),
        (
            "Event source",
            {
                "event_type": "vehicle.registered",
                "source": "",
            },
        ),
        (
            "Schema version",
            {
                "event_type": "vehicle.registered",
                "source": "vehicle-api",
                "schema_version": " ",
            },
        ),
    ],
)
def test_event_envelope_rejects_empty_required_values(
    field_name: str,
    kwargs: dict[str, str],
) -> None:
    with pytest.raises(
        ValueError,
        match=field_name,
    ):
        create_event_envelope(
            **kwargs,
            payload={},
        )


def test_event_envelope_rejects_naive_timestamp() -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        create_event_envelope(
            event_type="vehicle.registered",
            source="vehicle-service",
            occurred_at=datetime(
                2026,
                10,
                3,
                2,
                0,
            ),
            payload={},
        )
