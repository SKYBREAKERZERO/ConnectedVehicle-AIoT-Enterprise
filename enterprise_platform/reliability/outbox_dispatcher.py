from __future__ import annotations

import random
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.serialization import (
    EventSerializationError,
    deserialize_event_envelope,
)
from enterprise_platform.messaging.sqs import SQSBatchSendResult
from enterprise_platform.reliability.circuit_breaker import CircuitGate, CircuitPermit
from enterprise_platform.reliability.failure import (
    ExceptionTypeFailureClassifier,
    FailureClassifier,
    FailureDisposition,
)
from enterprise_platform.reliability.outbox import (
    ClaimedOutboxEvent,
)
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.reliability.retry import (
    calculate_retry_delay,
)
from enterprise_platform.reliability.retry_budget import RetryBudget

OutboxPublishFunction = Callable[
    [EventEnvelope],
    Awaitable[object],
]

OutboxBatchPublishFunction = Callable[
    [tuple[EventEnvelope, ...]], Awaitable[tuple[SQSBatchSendResult, ...]]
]


class OutboxBatchMarkFunction(Protocol):
    async def __call__(
        self, *, claims: tuple[ClaimedOutboxEvent, ...], published_at: datetime
    ) -> tuple[str, ...]: ...


class OutboxRetryDeferFunction(Protocol):
    async def __call__(
        self, *, claims: tuple[ClaimedOutboxEvent, ...], available_at: datetime
    ) -> int: ...


Clock = Callable[[], datetime]
RandomFunction = Callable[[], float]


class UnknownOutboxDestinationError(RuntimeError):
    """Raised when an outbox logical destination has no publisher."""

    def __init__(
        self,
        destination: str,
    ) -> None:
        super().__init__(f"No outbox publisher is registered for destination {destination!r}.")
        self.destination = destination


class OutboxStore(Protocol):
    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]: ...

    async def release_unattempted(self, *, claims: tuple[ClaimedOutboxEvent, ...]) -> int: ...

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
    ) -> bool: ...

    async def mark_failed(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        failed_at: datetime,
        failure_code: str,
    ) -> bool: ...

    async def schedule_retry(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        available_at: datetime,
    ) -> bool: ...


class MappingOutboxDestinationResolver:
    """Maps logical outbox destinations to transport publishers."""

    def __init__(
        self,
        publishers: Mapping[
            str,
            OutboxPublishFunction,
        ],
    ) -> None:
        normalized: dict[
            str,
            OutboxPublishFunction,
        ] = {}

        for destination, publisher in publishers.items():
            normalized_destination = destination.strip()

            if not normalized_destination:
                raise ValueError("Outbox destination must not be empty.")

            if normalized_destination in normalized:
                raise ValueError(
                    f"Duplicate normalized outbox destination: {normalized_destination!r}."
                )

            normalized[normalized_destination] = publisher

        if not normalized:
            raise ValueError("At least one outbox destination publisher must be configured.")

        self._publishers = normalized

    def resolve(
        self,
        destination: str,
    ) -> OutboxPublishFunction:
        normalized_destination = destination.strip()

        if not normalized_destination:
            raise ValueError("Outbox destination must not be empty.")

        try:
            return self._publishers[normalized_destination]
        except KeyError as exc:
            raise UnknownOutboxDestinationError(normalized_destination) from exc


@dataclass(frozen=True, slots=True)
class OutboxDispatchBatchResult:
    claimed: int
    published: int
    retries_scheduled: int
    stale_claims: int
    failed: int = 0
    released_unattempted: int = 0
    retry_budget_deferred: int = 0


class OutboxDispatcher:
    """Publishes leased outbox events without holding DB locks."""

    def __init__(
        self,
        *,
        store: OutboxStore,
        destinations: MappingOutboxDestinationResolver,
        retry_policy: RetryPolicy,
        failure_classifier: FailureClassifier | None = None,
        batch_size: int = 100,
        lease_seconds: int = 30,
        clock: Clock | None = None,
        random_value: RandomFunction = random.random,
        circuit: CircuitGate | None = None,
        batch_publisher: OutboxBatchPublishFunction | None = None,
        batch_mark_published: OutboxBatchMarkFunction | None = None,
        batch_destination: str | None = None,
        retry_budget: RetryBudget | None = None,
        retry_deferrer: OutboxRetryDeferFunction | None = None,
    ) -> None:
        if not 1 <= batch_size <= 1000:
            raise ValueError("Outbox dispatcher batch_size must be between 1 and 1000.")

        if lease_seconds < 1:
            raise ValueError("Outbox dispatcher lease_seconds must be at least 1.")

        self._store = store
        self._destinations = destinations
        self._retry_policy = retry_policy
        self._failure_classifier = (
            failure_classifier
            if failure_classifier is not None
            else ExceptionTypeFailureClassifier((MessagePublishError,))
        )
        self._batch_size = batch_size
        self._lease_seconds = lease_seconds
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)
        self._random_value = random_value
        self._circuit = circuit
        batch_configured = any(
            value is not None
            for value in (batch_publisher, batch_mark_published, batch_destination)
        )
        if batch_configured and (
            batch_publisher is None
            or batch_mark_published is None
            or not batch_destination
            or batch_destination.strip() != batch_destination
        ):
            raise ValueError("Batch mode requires destination, publisher and acknowledger")
        self._batch_publisher = batch_publisher
        self._batch_mark_published = batch_mark_published
        self._batch_destination = batch_destination
        if (retry_budget is None) != (retry_deferrer is None):
            raise ValueError("Retry budget requires a fenced PostgreSQL deferrer")
        self._retry_budget = retry_budget
        self._retry_deferrer = retry_deferrer

    async def dispatch_batch(
        self,
        *,
        now: datetime | None = None,
    ) -> OutboxDispatchBatchResult:
        # Acquire before touching PostgreSQL. A CLOSED permit authorizes a
        # bounded batch; HALF_OPEN / rate-limited permits authorize only one.
        permit = await self._circuit.acquire() if self._circuit is not None else None
        if permit is not None and not permit.allowed:
            return OutboxDispatchBatchResult(0, 0, 0, 0)

        capacity = self._batch_size
        if permit is not None:
            capacity = min(capacity, max(1, permit.max_batch))
        try:
            claimed_events = await self._store.claim_batch(
                batch_size=capacity,
                lease_seconds=self._lease_seconds,
                now=now,
            )
        except BaseException:
            if permit is not None and self._circuit is not None:
                await self._circuit.release(permit)
            raise

        if not claimed_events:
            if permit is not None and self._circuit is not None:
                await self._circuit.release(permit)
            return OutboxDispatchBatchResult(0, 0, 0, 0)

        # Retry tokens are reserved ONLY for attempts > 1, before any SQS side
        # effect. A denied retry is delayed in PostgreSQL and its newly added
        # claim attempt is refunded via live (id, claim_token, lease) fencing.
        # Redis failure denies all retries; it never silently bypasses the budget.
        budget_deferred = 0
        budget_stale = 0
        if self._retry_budget is not None and self._retry_deferrer is not None:
            retries = tuple(item for item in claimed_events if item.attempts > 1)
            if retries:
                try:
                    allowed_count = await self._retry_budget.acquire(len(retries))
                except Exception:
                    # Redis unavailability/invalid permits deny ALL retry sends.
                    allowed_count = 0
                except BaseException:
                    # Cancellation can arrive after PG Claim but before any send.
                    # Refund only unattempted live leases; never burn attempts.
                    await self._store.release_unattempted(claims=claimed_events)
                    if permit is not None and self._circuit is not None:
                        await self._circuit.release(permit)
                    raise
                denied = retries[allowed_count:]
                if denied:
                    try:
                        budget_deferred = await self._retry_deferrer(
                            claims=denied,
                            available_at=self._now()
                            + timedelta(seconds=self._retry_budget.policy.defer_seconds),
                        )
                    except BaseException:
                        # If deferral fails, never send any claim. Tokens may be
                        # lost, but no retry will bypass the budget.
                        await self._store.release_unattempted(claims=claimed_events)
                        if permit is not None and self._circuit is not None:
                            await self._circuit.release(permit)
                        raise
                    budget_stale = len(denied) - budget_deferred
                    denied_ids = {item.id for item in denied}
                    claimed_events = tuple(
                        item for item in claimed_events if item.id not in denied_ids
                    )
                if not claimed_events:
                    if permit is not None and self._circuit is not None:
                        await self._circuit.release(permit)
                    return OutboxDispatchBatchResult(
                        claimed=len(retries),
                        published=0,
                        retries_scheduled=0,
                        stale_claims=budget_stale,
                        retry_budget_deferred=budget_deferred,
                    )

        original_claimed = len(claimed_events) + budget_deferred + budget_stale
        if (
            self._batch_publisher is not None
            and self._batch_mark_published is not None
            and len(claimed_events) > 1
            and (permit is None or (not permit.token and permit.max_batch > 1))
            and all(item.destination == self._batch_destination for item in claimed_events)
        ):
            result = await self._dispatch_sqs_batches(claimed_events, permit)
            return replace(
                result,
                claimed=original_claimed,
                stale_claims=result.stale_claims + budget_stale,
                retry_budget_deferred=budget_deferred,
            )

        published = 0
        retries_scheduled = 0
        stale_claims = 0
        failed = 0
        released = 0
        started_count = 0

        try:
            for index, claimed in enumerate(claimed_events):
                # After this point the external send outcome may be unknown.
                # Never refund this claim, even if the operation is cancelled.
                started_count = index + 1
                opened = False
                try:
                    event = deserialize_event_envelope(claimed.event_body)
                    publisher = self._destinations.resolve(claimed.destination)
                    await publisher(event)
                except Exception as exc:
                    disposition = self._failure_classifier.classify(exc)
                    if permit is not None and self._circuit is not None:
                        if disposition is FailureDisposition.RETRYABLE:
                            opened = await self._circuit.failure(permit)
                        else:
                            await self._circuit.release(permit)

                    if (
                        disposition is FailureDisposition.NON_RETRYABLE
                        or claimed.attempts >= self._retry_policy.max_attempts
                    ):
                        code = (
                            "non_retryable"
                            if disposition is FailureDisposition.NON_RETRYABLE
                            else "retry_exhausted"
                        )
                        updated = await self._store.mark_failed(
                            outbox_id=claimed.id,
                            claim_token=claimed.claim_token,
                            failed_at=self._now(),
                            failure_code=code,
                        )
                        if updated:
                            failed += 1
                        else:
                            stale_claims += 1
                    else:
                        updated = await self._schedule_retry(claimed)
                        if updated:
                            retries_scheduled += 1
                        else:
                            stale_claims += 1

                    if opened:
                        # Any remaining events have not been sent. Revoke their
                        # claims atomically with lease-token fencing and refund
                        # exactly the attempts added by this claim.
                        break
                    continue

                if permit is not None and self._circuit is not None:
                    await self._circuit.success(permit)

                marked = await self._store.mark_published(
                    outbox_id=claimed.id,
                    claim_token=claimed.claim_token,
                    published_at=self._now(),
                )
                if marked:
                    published += 1
                else:
                    stale_claims += 1
        finally:
            remaining = claimed_events[started_count:]
            if remaining:
                released = await self._store.release_unattempted(claims=remaining)
                stale_claims += len(remaining) - released

        return OutboxDispatchBatchResult(
            claimed=original_claimed,
            published=published,
            retries_scheduled=retries_scheduled,
            stale_claims=stale_claims + budget_stale,
            failed=failed,
            released_unattempted=released,
            retry_budget_deferred=budget_deferred,
        )

    async def _dispatch_sqs_batches(
        self,
        claims: tuple[ClaimedOutboxEvent, ...],
        permit: CircuitPermit | None,
    ) -> OutboxDispatchBatchResult:
        """Track per-entry outcomes and batch-commit only acknowledged successes.

        Once a subbatch is attempted, all its entries may have unknown outcomes
        on HTTP response loss. Never refund an attempted subbatch. Only the
        untouched tail can be released if the circuit opens or the task stops.
        """
        assert self._batch_publisher is not None
        assert self._batch_mark_published is not None
        published = 0
        retries_scheduled = 0
        stale_claims = 0
        failed = 0
        released = 0
        attempted = 0
        try:
            for offset in range(0, len(claims), 10):
                group = claims[offset : offset + 10]
                attempted = offset + len(group)
                valid: list[tuple[ClaimedOutboxEvent, EventEnvelope]] = []
                for claimed in group:
                    try:
                        event = deserialize_event_envelope(claimed.event_body)
                    except EventSerializationError:
                        updated = await self._store.mark_failed(
                            outbox_id=claimed.id,
                            claim_token=claimed.claim_token,
                            failed_at=self._now(),
                            failure_code="non_retryable",
                        )
                        failed += int(updated)
                        stale_claims += int(not updated)
                    else:
                        valid.append((claimed, event))

                opened = False
                if valid:
                    try:
                        outcomes = await self._batch_publisher(tuple(event for _, event in valid))
                        if len(outcomes) != len(valid) or any(
                            result.event_id != event.event_id
                            or result.status not in {"sent", "retryable", "permanent"}
                            for (_, event), result in zip(valid, outcomes, strict=True)
                        ):
                            raise MessagePublishError()
                    except MessagePublishError:
                        # HTTP response missing or invalid: none may be marked
                        # successful. Re-delivery is expected (at-least-once).
                        outcomes = tuple(
                            SQSBatchSendResult(event.event_id, "retryable") for _, event in valid
                        )

                    successful = tuple(
                        claimed
                        for (claimed, _), result in zip(valid, outcomes, strict=True)
                        if result.status == "sent"
                    )
                    if successful:
                        updated_ids = set(
                            await self._batch_mark_published(
                                claims=successful, published_at=self._now()
                            )
                        )
                        published += len(updated_ids)
                        stale_claims += len(successful) - len(updated_ids)

                    for (claimed, _), result in zip(valid, outcomes, strict=True):
                        if result.status == "sent":
                            continue
                        terminal = (
                            result.status == "permanent"
                            or claimed.attempts >= self._retry_policy.max_attempts
                        )
                        if terminal:
                            code = (
                                "non_retryable"
                                if result.status == "permanent"
                                else "retry_exhausted"
                            )
                            updated = await self._store.mark_failed(
                                outbox_id=claimed.id,
                                claim_token=claimed.claim_token,
                                failed_at=self._now(),
                                failure_code=code,
                            )
                            failed += int(updated)
                            stale_claims += int(not updated)
                        else:
                            updated = await self._schedule_retry(claimed)
                            retries_scheduled += int(updated)
                            stale_claims += int(not updated)

                    if permit is not None and self._circuit is not None:
                        if any(result.status == "retryable" for result in outcomes):
                            opened = await self._circuit.failure(permit)
                        else:
                            await self._circuit.success(permit)
                if opened:
                    break
        finally:
            untouched = claims[attempted:]
            if untouched:
                released = await self._store.release_unattempted(claims=untouched)
                stale_claims += len(untouched) - released

        return OutboxDispatchBatchResult(
            claimed=len(claims),
            published=published,
            retries_scheduled=retries_scheduled,
            stale_claims=stale_claims,
            failed=failed,
            released_unattempted=released,
        )

    async def _schedule_retry(
        self,
        claimed: ClaimedOutboxEvent,
    ) -> bool:
        delay_seconds = calculate_retry_delay(
            self._retry_policy,
            retry_number=max(
                1,
                claimed.attempts,
            ),
            random_value=self._random_value(),
        )

        available_at = self._now() + timedelta(seconds=delay_seconds)

        return await self._store.schedule_retry(
            outbox_id=claimed.id,
            claim_token=claimed.claim_token,
            available_at=available_at,
        )

    def _now(self) -> datetime:
        value = self._clock()

        if value.tzinfo is None:
            raise ValueError("Outbox dispatcher clock must return a timezone-aware datetime.")

        return value
