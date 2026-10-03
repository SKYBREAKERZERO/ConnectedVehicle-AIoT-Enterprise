from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

import pytest
from redis.exceptions import RedisError

from enterprise_platform.cache.client import CacheKeyBuilder
from enterprise_platform.reliability.exceptions import (
    IdempotencyStateError,
    IdempotencyStoreError,
)
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
)
from enterprise_platform.reliability.redis_idempotency import (
    RedisIdempotencyStore,
)


@dataclass
class FakeRedisScriptClient:
    results: list[object] = field(default_factory=list)
    error: RedisError | None = None
    calls: list[
        tuple[
            str,
            int,
            tuple[object, ...],
        ]
    ] = field(default_factory=list)

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> object:
        self.calls.append(
            (
                script,
                numkeys,
                keys_and_args,
            )
        )

        if self.error is not None:
            raise self.error

        if not self.results:
            raise AssertionError("No fake Redis result configured.")

        return self.results.pop(0)


def create_store(
    client: FakeRedisScriptClient,
) -> RedisIdempotencyStore:
    return RedisIdempotencyStore(
        client,
        key_builder=CacheKeyBuilder(prefix="connected-vehicle"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("redis_result", "expected"),
    [
        (
            "acquired",
            IdempotencyDecision.ACQUIRED,
        ),
        (
            "in_progress",
            IdempotencyDecision.IN_PROGRESS,
        ),
        (
            "completed",
            IdempotencyDecision.COMPLETED,
        ),
    ],
)
async def test_try_acquire_maps_redis_state(
    redis_result: str,
    expected: IdempotencyDecision,
) -> None:
    client = FakeRedisScriptClient(results=[redis_result])
    store = create_store(client)

    result = await store.try_acquire(
        "command-123",
        ttl_seconds=60,
    )

    assert result is expected


@pytest.mark.asyncio
async def test_try_acquire_uses_hashed_namespaced_key() -> None:
    client = FakeRedisScriptClient(results=["acquired"])
    store = create_store(client)

    await store.try_acquire(
        "command-123",
        ttl_seconds=60,
    )

    digest = sha256(b"command-123").hexdigest()

    _, numkeys, args = client.calls[0]

    assert numkeys == 1
    assert args == (
        f"connected-vehicle:idempotency:{digest}",
        60,
    )


@pytest.mark.asyncio
async def test_try_acquire_rejects_unknown_state() -> None:
    client = FakeRedisScriptClient(results=["corrupted"])
    store = create_store(client)

    with pytest.raises(IdempotencyStateError):
        await store.try_acquire(
            "command-123",
            ttl_seconds=60,
        )


@pytest.mark.asyncio
async def test_try_acquire_hides_redis_failure() -> None:
    client = FakeRedisScriptClient(error=RedisError("redis.internal:6379 secret detail"))
    store = create_store(client)

    with pytest.raises(IdempotencyStoreError) as exc_info:
        await store.try_acquire(
            "command-123",
            ttl_seconds=60,
        )

    assert "redis.internal" not in str(exc_info.value)
    assert "secret detail" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_mark_completed_accepts_completed_state() -> None:
    client = FakeRedisScriptClient(results=["completed"])
    store = create_store(client)

    await store.mark_completed(
        "command-123",
        ttl_seconds=3600,
    )

    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_mark_completed_rejects_missing_state() -> None:
    client = FakeRedisScriptClient(results=["missing"])
    store = create_store(client)

    with pytest.raises(IdempotencyStateError):
        await store.mark_completed(
            "command-123",
            ttl_seconds=3600,
        )


@pytest.mark.asyncio
async def test_release_executes_atomic_script() -> None:
    client = FakeRedisScriptClient(results=[1])
    store = create_store(client)

    await store.release("command-123")

    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_release_hides_redis_failure() -> None:
    client = FakeRedisScriptClient(error=RedisError("backend detail"))
    store = create_store(client)

    with pytest.raises(IdempotencyStoreError) as exc_info:
        await store.release("command-123")

    assert "backend detail" not in str(exc_info.value)
