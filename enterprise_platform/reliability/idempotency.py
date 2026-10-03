from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class IdempotencyDecision(StrEnum):
    """Result of an atomic idempotency acquisition attempt."""

    ACQUIRED = "acquired"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class IdempotencyStore(Protocol):
    """Atomic persistence boundary for idempotency state."""

    async def try_acquire(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> IdempotencyDecision: ...

    async def mark_completed(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> None: ...

    async def release(
        self,
        key: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class IdempotencyPolicy:
    """Defines TTL behavior for active and completed operations."""

    in_progress_ttl_seconds: int = 60
    completed_ttl_seconds: int = 86_400

    def __post_init__(self) -> None:
        if self.in_progress_ttl_seconds < 1:
            raise ValueError("in_progress_ttl_seconds must be at least 1.")

        if self.completed_ttl_seconds < 1:
            raise ValueError("completed_ttl_seconds must be at least 1.")


def normalize_idempotency_key(value: str) -> str:
    normalized = value.strip()

    if not normalized:
        raise ValueError("idempotency key must not be empty.")

    if len(normalized) > 255:
        raise ValueError("idempotency key must not exceed 255 characters.")

    return normalized


class IdempotencyService:
    """Coordinates idempotency without depending on a concrete backend."""

    def __init__(
        self,
        store: IdempotencyStore,
        *,
        policy: IdempotencyPolicy | None = None,
    ) -> None:
        self._store = store
        self._policy = policy or IdempotencyPolicy()

    async def begin(
        self,
        key: str,
    ) -> IdempotencyDecision:
        normalized_key = normalize_idempotency_key(key)

        return await self._store.try_acquire(
            normalized_key,
            ttl_seconds=self._policy.in_progress_ttl_seconds,
        )

    async def complete(
        self,
        key: str,
    ) -> None:
        normalized_key = normalize_idempotency_key(key)

        await self._store.mark_completed(
            normalized_key,
            ttl_seconds=self._policy.completed_ttl_seconds,
        )

    async def abandon(
        self,
        key: str,
    ) -> None:
        normalized_key = normalize_idempotency_key(key)

        await self._store.release(normalized_key)
