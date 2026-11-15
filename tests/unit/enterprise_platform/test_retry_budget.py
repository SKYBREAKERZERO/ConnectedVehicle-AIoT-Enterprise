"""Cost-02 contracts: retry permits do not change first-send or fencing semantics."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.serialization import serialize_event_envelope
from enterprise_platform.messaging.sqs import SQSBatchSendResult
from enterprise_platform.reliability.outbox import ClaimedOutboxEvent
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.reliability.retry_budget import RetryBudgetPolicy


@dataclass
class FakeBudget:
    grant: int
    policy: RetryBudgetPolicy = field(
        default_factory=lambda: RetryBudgetPolicy(rate_per_second=1, burst=2)
    )
    fail: bool = False
    cancel: bool = False
    requests: list[int] = field(default_factory=list)

    async def acquire(self, requested: int = 1) -> int:
        self.requests.append(requested)
        if self.cancel:
            raise asyncio.CancelledError()
        if self.fail:
            raise ConnectionError("redis unavailable")
        return min(self.grant, requested)


@dataclass
class RecordingStore:
    claims: tuple[ClaimedOutboxEvent, ...]
    deferred: list[tuple[str, ...]] = field(default_factory=list)
    delayed_until: datetime | None = None
    published: list[str] = field(default_factory=list)
    released: list[str] = field(default_factory=list)

    async def claim_batch(
        self, *, batch_size: int = 100, lease_seconds: int = 30, now: datetime | None = None
    ) -> tuple[ClaimedOutboxEvent, ...]:
        return self.claims[:batch_size]

    async def release_unattempted(self, *, claims: tuple[ClaimedOutboxEvent, ...]) -> int:
        self.released.extend(x.id for x in claims)
        return len(claims)

    async def defer_unattempted(
        self, *, claims: tuple[ClaimedOutboxEvent, ...], available_at: datetime
    ) -> int:
        self.deferred.append(tuple(x.id for x in claims))
        self.delayed_until = available_at
        return len(claims)

    async def mark_published_batch(
        self, *, claims: tuple[ClaimedOutboxEvent, ...], published_at: datetime
    ) -> tuple[str, ...]:
        self.published.extend(x.id for x in claims)
        return tuple(x.id for x in claims)

    async def mark_published(
        self, *, outbox_id: str, claim_token: str, published_at: datetime | None = None
    ) -> bool:
        self.published.append(outbox_id)
        return True

    async def mark_failed(
        self, *, outbox_id: str, claim_token: str, failed_at: datetime, failure_code: str
    ) -> bool:
        raise AssertionError("Unexpected terminal failure")

    async def schedule_retry(
        self, *, outbox_id: str, claim_token: str, available_at: datetime
    ) -> bool:
        raise AssertionError("Unexpected retry scheduling")


def make_claims(attempts: tuple[int, ...]) -> tuple[ClaimedOutboxEvent, ...]:
    return tuple(
        ClaimedOutboxEvent(
            id=str(uuid4()),
            event_id=f"retry-budget-{uuid4().hex}",
            event_type="vehicle.command.requested",
            destination="vehicle-command",
            event_body=serialize_event_envelope(
                create_event_envelope(
                    event_type="vehicle.command.requested",
                    source="cost02-contract",
                    payload={"vehicle_id": "VIN-COST02", "command": "lock"},
                )
            ),
            attempts=attempt,
            claim_token=str(uuid4()),
            lease_expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )
        for attempt in attempts
    )


def dispatcher(store: RecordingStore, budget: FakeBudget) -> OutboxDispatcher:
    async def single(_event: object) -> None:
        raise AssertionError("Batch send required")

    async def batched(
        events: tuple[EventEnvelope, ...],
    ) -> tuple[SQSBatchSendResult, ...]:
        return tuple(SQSBatchSendResult(event.event_id, "sent") for event in events)

    return OutboxDispatcher(
        store=store,
        destinations=MappingOutboxDestinationResolver({"vehicle-command": single}),
        retry_policy=RetryPolicy(max_attempts=5),
        batch_size=10,
        batch_destination="vehicle-command",
        batch_publisher=batched,
        batch_mark_published=store.mark_published_batch,
        retry_budget=budget,
        retry_deferrer=store.defer_unattempted,
    )


@pytest.mark.asyncio
async def test_cost02_first_attempt_is_not_charged_retry_budget() -> None:
    store = RecordingStore(make_claims((1, 1, 1)))
    budget = FakeBudget(grant=0)
    result = await dispatcher(store, budget).dispatch_batch()
    assert result.claimed == result.published == 3
    assert result.retry_budget_deferred == 0
    assert budget.requests == []
    assert store.deferred == []


@pytest.mark.asyncio
async def test_cost02_budget_denial_defers_only_retries_before_sqs() -> None:
    claims = make_claims((1, 2, 2, 2))
    store = RecordingStore(claims)
    budget = FakeBudget(grant=1)
    result = await dispatcher(store, budget).dispatch_batch()
    assert budget.requests == [3]
    assert result.claimed == 4
    assert result.published == 2
    assert result.retry_budget_deferred == 2
    assert result.stale_claims == 0
    assert set(store.published) == {claims[0].id, claims[1].id}
    assert store.deferred == [(claims[2].id, claims[3].id)]
    assert store.delayed_until is not None and store.delayed_until > datetime.now(UTC)


@pytest.mark.asyncio
async def test_cost02_redis_failure_denies_retries_but_not_first_send() -> None:
    claims = make_claims((2, 1, 2))
    store = RecordingStore(claims)
    budget = FakeBudget(grant=3, fail=True)
    result = await dispatcher(store, budget).dispatch_batch()
    assert result.claimed == 3
    assert result.published == 1
    assert result.retry_budget_deferred == 2
    assert store.published == [claims[1].id]
    assert store.deferred == [(claims[0].id, claims[2].id)]


@pytest.mark.asyncio
async def test_cost02_cancellation_refunds_unattempted_claims() -> None:
    claims = make_claims((1, 2, 2))
    store = RecordingStore(claims)
    budget = FakeBudget(grant=1, cancel=True)
    with pytest.raises(asyncio.CancelledError):
        await dispatcher(store, budget).dispatch_batch()
    assert store.released == [claim.id for claim in claims]
    assert store.published == []


@pytest.mark.asyncio
async def test_cost02_zero_budget_never_sends_or_consumes_retry() -> None:
    claims = make_claims((2, 3))
    store = RecordingStore(claims)
    budget = FakeBudget(grant=0)
    result = await dispatcher(store, budget).dispatch_batch()
    assert result.claimed == 2
    assert result.published == 0
    assert result.retry_budget_deferred == 2
    assert store.published == []
    assert store.deferred == [(claims[0].id, claims[1].id)]


def test_cost02_budget_requires_fenced_deferrer() -> None:
    store = RecordingStore(make_claims((2,)))

    async def single(_event: EventEnvelope) -> None:
        raise AssertionError("Must not send when budget construction fails")

    with pytest.raises(ValueError, match="fenced"):
        OutboxDispatcher(
            store=store,
            destinations=MappingOutboxDestinationResolver({"vehicle-command": single}),
            retry_policy=RetryPolicy(),
            retry_budget=FakeBudget(grant=1),
        )


@pytest.mark.parametrize(
    "rate,burst",
    [(0.0, 1), (float("nan"), 1), (float("inf"), 1), (1.0, 0), (1.0, 10001)],
)
def test_cost02_invalid_budget_policy_is_rejected(rate: float, burst: int) -> None:
    with pytest.raises(ValueError):
        RetryBudgetPolicy(rate_per_second=rate, burst=burst)
