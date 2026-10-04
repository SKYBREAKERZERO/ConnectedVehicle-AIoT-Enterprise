from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from enterprise_platform.messaging.envelope import (
    EventEnvelope,
    create_event_envelope,
)
from enterprise_platform.messaging.exceptions import (
    MessagePublishError,
)
from enterprise_platform.messaging.serialization import (
    serialize_event_envelope,
)
from enterprise_platform.reliability.outbox import (
    ClaimedOutboxEvent,
)
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
    UnknownOutboxDestinationError,
)
from enterprise_platform.reliability.policies import (
    RetryPolicy,
)


@dataclass
class FakeOutboxStore:
    claimed_events: tuple[
        ClaimedOutboxEvent,
        ...,
    ] = ()

    mark_published_result: bool = True
    schedule_retry_result: bool = True

    claim_calls: list[
        tuple[
            int,
            int,
            datetime | None,
        ]
    ] = field(default_factory=list)

    mark_calls: list[
        tuple[
            str,
            str,
            datetime | None,
        ]
    ] = field(default_factory=list)

    retry_calls: list[
        tuple[
            str,
            str,
            datetime,
        ]
    ] = field(default_factory=list)

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        self.claim_calls.append(
            (
                batch_size,
                lease_seconds,
                now,
            )
        )

        return self.claimed_events

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
    ) -> bool:
        self.mark_calls.append(
            (
                outbox_id,
                claim_token,
                published_at,
            )
        )

        return self.mark_published_result

    async def schedule_retry(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        available_at: datetime,
    ) -> bool:
        self.retry_calls.append(
            (
                outbox_id,
                claim_token,
                available_at,
            )
        )

        return self.schedule_retry_result


def create_claimed_event(
    *,
    destination: str = "vehicle-command",
    attempts: int = 1,
) -> tuple[
    ClaimedOutboxEvent,
    EventEnvelope,
]:
    event = create_event_envelope(
        event_id=f"event-{uuid4()}",
        event_type="vehicle.command.requested",
        source="outbox-dispatcher-test",
        payload={
            "vehicle_id": "VIN-DISPATCH-001",
            "command": "lock",
        },
    )

    claimed = ClaimedOutboxEvent(
        id=str(uuid4()),
        event_id=event.event_id,
        event_type=event.event_type,
        destination=destination,
        event_body=serialize_event_envelope(event),
        attempts=attempts,
        claim_token=str(uuid4()),
        lease_expires_at=datetime(
            2030,
            1,
            1,
            0,
            1,
            tzinfo=UTC,
        ),
    )

    return claimed, event


def create_retry_policy() -> RetryPolicy:
    return RetryPolicy(
        max_attempts=5,
        base_delay_seconds=2.0,
        max_delay_seconds=30.0,
        jitter_ratio=0.0,
    )


@pytest.mark.asyncio
async def test_dispatcher_publishes_and_marks_event() -> None:
    now = datetime(
        2030,
        1,
        1,
        tzinfo=UTC,
    )

    claimed, original_event = create_claimed_event()

    store = FakeOutboxStore(
        claimed_events=(claimed,),
    )

    published_events: list[EventEnvelope] = []

    async def publisher(
        event: EventEnvelope,
    ) -> str:
        published_events.append(event)
        return "message-001"

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        batch_size=25,
        lease_seconds=45,
        clock=lambda: now,
        random_value=lambda: 0.5,
    )

    result = await dispatcher.dispatch_batch(now=now)

    assert result.claimed == 1
    assert result.published == 1
    assert result.retries_scheduled == 0
    assert result.stale_claims == 0

    assert store.claim_calls == [
        (
            25,
            45,
            now,
        )
    ]

    assert len(published_events) == 1

    published_event = published_events[0]

    assert published_event.event_id == original_event.event_id
    assert published_event.event_type == original_event.event_type
    assert dict(published_event.payload) == dict(original_event.payload)

    assert store.mark_calls == [
        (
            claimed.id,
            claimed.claim_token,
            now,
        )
    ]

    assert store.retry_calls == []


@pytest.mark.asyncio
async def test_dispatcher_persists_retry_with_exponential_backoff() -> None:
    now = datetime(
        2030,
        2,
        1,
        tzinfo=UTC,
    )

    claimed, _ = create_claimed_event(
        attempts=3,
    )

    store = FakeOutboxStore(
        claimed_events=(claimed,),
    )

    async def publisher(
        event: EventEnvelope,
    ) -> None:
        raise MessagePublishError()

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        clock=lambda: now,
        random_value=lambda: 0.5,
    )

    result = await dispatcher.dispatch_batch(now=now)

    # attempts=3 means this failure uses retry number 3:
    #
    # base 2s
    # retry 1 -> 2s
    # retry 2 -> 4s
    # retry 3 -> 8s
    expected_available_at = now + timedelta(seconds=8)

    assert result.claimed == 1
    assert result.published == 0
    assert result.retries_scheduled == 1
    assert result.stale_claims == 0

    assert store.mark_calls == []

    assert store.retry_calls == [
        (
            claimed.id,
            claimed.claim_token,
            expected_available_at,
        )
    ]


@pytest.mark.asyncio
async def test_dispatcher_counts_stale_claim_when_publish_mark_is_fenced() -> None:
    now = datetime(
        2030,
        3,
        1,
        tzinfo=UTC,
    )

    claimed, _ = create_claimed_event()

    store = FakeOutboxStore(
        claimed_events=(claimed,),
        mark_published_result=False,
    )

    async def publisher(
        event: EventEnvelope,
    ) -> str:
        return "message-001"

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        clock=lambda: now,
    )

    result = await dispatcher.dispatch_batch(now=now)

    assert result.claimed == 1
    assert result.published == 0
    assert result.retries_scheduled == 0
    assert result.stale_claims == 1

    assert len(store.mark_calls) == 1
    assert store.retry_calls == []


@pytest.mark.asyncio
async def test_dispatcher_counts_stale_claim_when_retry_update_is_fenced() -> None:
    now = datetime(
        2030,
        4,
        1,
        tzinfo=UTC,
    )

    claimed, _ = create_claimed_event()

    store = FakeOutboxStore(
        claimed_events=(claimed,),
        schedule_retry_result=False,
    )

    async def publisher(
        event: EventEnvelope,
    ) -> None:
        raise MessagePublishError()

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        clock=lambda: now,
        random_value=lambda: 0.5,
    )

    result = await dispatcher.dispatch_batch(now=now)

    assert result.claimed == 1
    assert result.published == 0
    assert result.retries_scheduled == 0
    assert result.stale_claims == 1

    assert store.mark_calls == []
    assert len(store.retry_calls) == 1


@pytest.mark.asyncio
async def test_dispatcher_rejects_unknown_destination() -> None:
    now = datetime(
        2030,
        5,
        1,
        tzinfo=UTC,
    )

    claimed, _ = create_claimed_event(
        destination="unknown-destination",
    )

    store = FakeOutboxStore(
        claimed_events=(claimed,),
    )

    async def publisher(
        event: EventEnvelope,
    ) -> str:
        return "unused"

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        clock=lambda: now,
    )

    with pytest.raises(
        UnknownOutboxDestinationError,
        match="unknown-destination",
    ):
        await dispatcher.dispatch_batch(now=now)

    assert store.mark_calls == []
    assert store.retry_calls == []


@pytest.mark.asyncio
async def test_dispatcher_does_not_retry_non_retryable_failure() -> None:
    now = datetime(
        2030,
        6,
        1,
        tzinfo=UTC,
    )

    claimed, _ = create_claimed_event()

    store = FakeOutboxStore(
        claimed_events=(claimed,),
    )

    async def publisher(
        event: EventEnvelope,
    ) -> None:
        raise ValueError("permanent publish failure")

    destinations = MappingOutboxDestinationResolver(
        {
            "vehicle-command": publisher,
        }
    )

    dispatcher = OutboxDispatcher(
        store=store,
        destinations=destinations,
        retry_policy=create_retry_policy(),
        clock=lambda: now,
    )

    with pytest.raises(
        ValueError,
        match="permanent publish failure",
    ):
        await dispatcher.dispatch_batch(now=now)

    assert store.mark_calls == []
    assert store.retry_calls == []
