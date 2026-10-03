from __future__ import annotations

from datetime import UTC, datetime

import pytest

from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.messaging.serialization import (
    deserialize_event_envelope,
)
from enterprise_platform.reliability.outbox import (
    PendingOutboxEvent,
)


def test_pending_outbox_event_preserves_event_envelope() -> None:
    event = create_event_envelope(
        event_id="event-001",
        event_type="vehicle.command.requested",
        source="vehicle-api",
        correlation_id="correlation-001",
        trace_id="trace-001",
        payload={
            "vehicle_id": "VIN001",
            "command": "unlock",
        },
    )

    created_at = datetime(
        2026,
        10,
        3,
        10,
        0,
        tzinfo=UTC,
    )

    outbox = PendingOutboxEvent.from_event(
        event,
        destination="vehicle-command",
        created_at=created_at,
    )

    assert outbox.event_id == "event-001"
    assert outbox.event_type == ("vehicle.command.requested")
    assert outbox.destination == "vehicle-command"
    assert outbox.created_at == created_at
    assert outbox.available_at == created_at
    assert deserialize_event_envelope(outbox.event_body) == event


def test_pending_outbox_event_normalizes_destination() -> None:
    event = create_event_envelope(
        event_type="vehicle.test",
        source="test",
        payload={},
    )

    outbox = PendingOutboxEvent.from_event(
        event,
        destination="  vehicle-command  ",
    )

    assert outbox.destination == "vehicle-command"


def test_pending_outbox_event_rejects_empty_destination() -> None:
    event = create_event_envelope(
        event_type="vehicle.test",
        source="test",
        payload={},
    )

    with pytest.raises(ValueError):
        PendingOutboxEvent.from_event(
            event,
            destination="   ",
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "created_at",
        "available_at",
    ],
)
def test_pending_outbox_event_rejects_naive_datetime(
    field_name: str,
) -> None:
    event = create_event_envelope(
        event_type="vehicle.test",
        source="test",
        payload={},
    )

    kwargs = {
        "created_at": datetime.now(UTC),
        "available_at": datetime.now(UTC),
    }

    kwargs[field_name] = datetime(
        2026,
        10,
        3,
        10,
        0,
    )

    with pytest.raises(ValueError):
        PendingOutboxEvent.from_event(
            event,
            destination="vehicle-command",
            **kwargs,
        )
