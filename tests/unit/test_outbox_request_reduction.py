"""Cost-01D: request reduction without sacrificing durable Outbox delivery."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.reliability.failure import ExceptionTypeFailureClassifier
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatchBatchResult,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.reliability.retry import run_with_retry
from enterprise_platform.runtime.process import bounded_idle_poll_delay, run_worker


def test_cost01d_idle_backoff_bounds_and_reset_contract() -> None:
    """Consecutive empty polls back off; a nonempty poll uses the normal interval."""
    intervals = [
        bounded_idle_poll_delay(
            base_interval=1.0, max_interval=5.0, consecutive_idle=n, jitter_value=1.0
        )
        for n in range(1, 8)
    ]
    assert intervals == [2.0, 4.0, 5.0, 5.0, 5.0, 5.0, 5.0]
    assert bounded_idle_poll_delay(
        base_interval=1.0, max_interval=5.0, consecutive_idle=4, jitter_value=0.0
    ) == 4.0
    with pytest.raises(ValueError):
        bounded_idle_poll_delay(
            base_interval=1.0, max_interval=0.5, consecutive_idle=1, jitter_value=0.5
        )


@pytest.mark.asyncio
async def test_cost01d_runtime_empty_poll_uses_adaptive_path() -> None:
    """The production worker loop invokes idle classification and exits cleanly."""
    stop = asyncio.Event()
    seen: list[int] = []

    async def operation() -> object:
        index = len(seen)
        seen.append(index)
        if index == 3:
            stop.set()
        return OutboxDispatchBatchResult(
            claimed=0 if index < 2 else 1,
            published=0,
            retries_scheduled=0,
            stale_claims=0,
        )

    classified: list[int] = []

    def is_idle(result: object) -> bool:
        assert isinstance(result, OutboxDispatchBatchResult)
        classified.append(result.claimed)
        return result.claimed == 0

    await asyncio.wait_for(
        run_worker(
            operation,
            stop=stop,
            poll_interval=0.001,
            error_delay=0.001,
            shutdown_timeout=0.1,
            operation_timeout=1.0,
            idle_result=is_idle,
            max_idle_poll_interval=0.02,
        ),
        timeout=2.0,
    )
    assert seen == [0, 1, 2, 3]
    assert classified == [0, 0, 1, 1]


@pytest.mark.asyncio
async def test_cost01d_empty_outbox_does_not_call_sqs() -> None:
    class EmptyStore:
        claims = 0

        async def claim_batch(
            self,
            *,
            batch_size: int = 100,
            lease_seconds: int = 30,
            now: datetime | None = None,
        ) -> tuple[()]:
            self.claims += 1
            return ()

    store = EmptyStore()
    sent: list[str] = []

    async def publisher(event: EventEnvelope) -> None:
        sent.append(event.event_id)

    # The remaining store methods are unreachable when the claim is empty.
    dispatcher = OutboxDispatcher(
        store=store,  # type: ignore[arg-type]
        destinations=MappingOutboxDestinationResolver({"remote-command": publisher}),
        retry_policy=RetryPolicy(max_attempts=3),
        batch_size=20,
        clock=lambda: datetime.now(UTC),
    )
    outcome = await dispatcher.dispatch_batch()
    assert outcome.claimed == 0
    assert outcome.published == 0
    assert store.claims == 1
    assert sent == []


@pytest.mark.asyncio
async def test_cost01d_permanent_failure_does_not_generate_retry_storm() -> None:
    calls = 0
    sleeps = 0

    async def failing_operation() -> None:
        nonlocal calls
        calls += 1
        raise ValueError("permanent")

    async def fake_sleep(delay: float) -> None:
        nonlocal sleeps
        sleeps += 1

    with pytest.raises(ValueError, match="permanent"):
        await run_with_retry(
            failing_operation,
            operation_name="cost01d",
            policy=RetryPolicy(max_attempts=20),
            failure_classifier=ExceptionTypeFailureClassifier((ConnectionError,)),
            sleep=fake_sleep,
        )
    assert calls == 1
    assert sleeps == 0
