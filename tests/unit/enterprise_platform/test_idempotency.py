from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
    IdempotencyPolicy,
    IdempotencyService,
    normalize_idempotency_key,
)


@dataclass
class FakeIdempotencyStore:
    acquire_result: IdempotencyDecision = IdempotencyDecision.ACQUIRED
    acquired: list[tuple[str, int]] = field(default_factory=list)
    completed: list[tuple[str, int]] = field(default_factory=list)
    released: list[str] = field(default_factory=list)

    async def try_acquire(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> IdempotencyDecision:
        self.acquired.append(
            (
                key,
                ttl_seconds,
            )
        )
        return self.acquire_result

    async def mark_completed(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> None:
        self.completed.append(
            (
                key,
                ttl_seconds,
            )
        )

    async def release(
        self,
        key: str,
    ) -> None:
        self.released.append(key)


def test_normalize_idempotency_key_strips_whitespace() -> None:
    assert normalize_idempotency_key("  command-123  ") == "command-123"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
    ],
)
def test_normalize_idempotency_key_rejects_empty_value(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        normalize_idempotency_key(value)


def test_normalize_idempotency_key_rejects_oversized_value() -> None:
    with pytest.raises(ValueError):
        normalize_idempotency_key("x" * 256)


def test_idempotency_policy_defaults() -> None:
    policy = IdempotencyPolicy()

    assert policy.in_progress_ttl_seconds == 60
    assert policy.completed_ttl_seconds == 86_400


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("in_progress_ttl_seconds", 0),
        ("in_progress_ttl_seconds", -1),
        ("completed_ttl_seconds", 0),
        ("completed_ttl_seconds", -1),
    ],
)
def test_idempotency_policy_rejects_invalid_ttl(
    field_name: str,
    value: int,
) -> None:
    kwargs = {
        "in_progress_ttl_seconds": 60,
        "completed_ttl_seconds": 86_400,
    }
    kwargs[field_name] = value

    with pytest.raises(ValueError):
        IdempotencyPolicy(**kwargs)


@pytest.mark.asyncio
async def test_begin_acquires_normalized_key() -> None:
    store = FakeIdempotencyStore()

    service = IdempotencyService(
        store,
        policy=IdempotencyPolicy(
            in_progress_ttl_seconds=120,
            completed_ttl_seconds=3600,
        ),
    )

    result = await service.begin("  command-123  ")

    assert result is IdempotencyDecision.ACQUIRED
    assert store.acquired == [
        (
            "command-123",
            120,
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "decision",
    [
        IdempotencyDecision.IN_PROGRESS,
        IdempotencyDecision.COMPLETED,
    ],
)
async def test_begin_preserves_existing_state(
    decision: IdempotencyDecision,
) -> None:
    store = FakeIdempotencyStore(
        acquire_result=decision,
    )

    service = IdempotencyService(store)

    result = await service.begin("command-123")

    assert result is decision


@pytest.mark.asyncio
async def test_complete_uses_completed_ttl() -> None:
    store = FakeIdempotencyStore()

    service = IdempotencyService(
        store,
        policy=IdempotencyPolicy(
            in_progress_ttl_seconds=60,
            completed_ttl_seconds=7200,
        ),
    )

    await service.complete(" command-123 ")

    assert store.completed == [
        (
            "command-123",
            7200,
        )
    ]


@pytest.mark.asyncio
async def test_abandon_releases_key() -> None:
    store = FakeIdempotencyStore()
    service = IdempotencyService(store)

    await service.abandon(" command-123 ")

    assert store.released == ["command-123"]
