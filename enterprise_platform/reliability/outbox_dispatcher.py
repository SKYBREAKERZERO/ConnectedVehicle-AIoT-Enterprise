from __future__ import annotations

import random
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from enterprise_platform.messaging.envelope import EventEnvelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.serialization import (
    deserialize_event_envelope,
)
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

OutboxPublishFunction = Callable[
    [EventEnvelope],
    Awaitable[object],
]

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

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
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

    async def dispatch_batch(
        self,
        *,
        now: datetime | None = None,
    ) -> OutboxDispatchBatchResult:
        claimed_events = await self._store.claim_batch(
            batch_size=self._batch_size,
            lease_seconds=self._lease_seconds,
            now=now,
        )

        published = 0
        retries_scheduled = 0
        stale_claims = 0

        for claimed in claimed_events:
            event = deserialize_event_envelope(claimed.event_body)

            publisher = self._destinations.resolve(claimed.destination)

            try:
                await publisher(event)
            except Exception as exc:
                disposition = self._failure_classifier.classify(exc)

                if disposition is FailureDisposition.NON_RETRYABLE:
                    raise

                retry_scheduled = await self._schedule_retry(
                    claimed,
                )

                if retry_scheduled:
                    retries_scheduled += 1
                else:
                    stale_claims += 1

                continue

            published_at = self._now()

            marked = await self._store.mark_published(
                outbox_id=claimed.id,
                claim_token=claimed.claim_token,
                published_at=published_at,
            )

            if marked:
                published += 1
            else:
                stale_claims += 1

        return OutboxDispatchBatchResult(
            claimed=len(claimed_events),
            published=published,
            retries_scheduled=retries_scheduled,
            stale_claims=stale_claims,
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
