from __future__ import annotations

import asyncio
from hashlib import sha256
from typing import cast
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from enterprise_platform.cache.client import CacheKeyBuilder
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
)
from enterprise_platform.reliability.redis_idempotency import (
    RedisIdempotencyStore,
    RedisScriptClient,
)


def _create_test_resources() -> tuple[
    Redis,
    CacheKeyBuilder,
]:
    client = Redis(
        host="127.0.0.1",
        port=16379,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
    )

    key_builder = CacheKeyBuilder(prefix=f"connected-vehicle:integration:{uuid4().hex}")

    return client, key_builder


def _redis_key(
    key_builder: CacheKeyBuilder,
    idempotency_key: str,
) -> str:
    digest = sha256(idempotency_key.encode("utf-8")).hexdigest()

    return key_builder.build(
        "idempotency",
        digest,
    )


@pytest.mark.asyncio
async def test_redis_idempotency_allows_exactly_one_concurrent_acquisition() -> None:
    client, key_builder = _create_test_resources()

    store = RedisIdempotencyStore(
        cast(RedisScriptClient, client),
        key_builder=key_builder,
    )

    idempotency_key = "command-concurrent"
    redis_key = _redis_key(
        key_builder,
        idempotency_key,
    )

    try:
        assert await client.ping() is True

        results = await asyncio.gather(
            *(
                store.try_acquire(
                    idempotency_key,
                    ttl_seconds=60,
                )
                for _ in range(20)
            )
        )

        assert results.count(IdempotencyDecision.ACQUIRED) == 1

        assert results.count(IdempotencyDecision.IN_PROGRESS) == 19

        assert results.count(IdempotencyDecision.COMPLETED) == 0

    finally:
        await client.delete(redis_key)
        await client.aclose()


@pytest.mark.asyncio
async def test_redis_idempotency_completed_state_blocks_future_execution() -> None:
    client, key_builder = _create_test_resources()

    store = RedisIdempotencyStore(
        cast(RedisScriptClient, client),
        key_builder=key_builder,
    )

    idempotency_key = "command-completed"
    redis_key = _redis_key(
        key_builder,
        idempotency_key,
    )

    try:
        assert await client.ping() is True

        first = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert first is IdempotencyDecision.ACQUIRED

        await store.mark_completed(
            idempotency_key,
            ttl_seconds=3600,
        )

        results = await asyncio.gather(
            *(
                store.try_acquire(
                    idempotency_key,
                    ttl_seconds=60,
                )
                for _ in range(10)
            )
        )

        assert results == [IdempotencyDecision.COMPLETED] * 10

    finally:
        await client.delete(redis_key)
        await client.aclose()


@pytest.mark.asyncio
async def test_redis_idempotency_release_allows_reacquisition() -> None:
    client, key_builder = _create_test_resources()

    store = RedisIdempotencyStore(
        cast(RedisScriptClient, client),
        key_builder=key_builder,
    )

    idempotency_key = "command-abandoned"
    redis_key = _redis_key(
        key_builder,
        idempotency_key,
    )

    try:
        assert await client.ping() is True

        first = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert first is IdempotencyDecision.ACQUIRED

        await store.release(idempotency_key)

        second = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert second is IdempotencyDecision.ACQUIRED

    finally:
        await client.delete(redis_key)
        await client.aclose()


@pytest.mark.asyncio
async def test_redis_idempotency_release_does_not_delete_completed_state() -> None:
    client, key_builder = _create_test_resources()

    store = RedisIdempotencyStore(
        cast(RedisScriptClient, client),
        key_builder=key_builder,
    )

    idempotency_key = "command-safe-release"
    redis_key = _redis_key(
        key_builder,
        idempotency_key,
    )

    try:
        assert await client.ping() is True

        first = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert first is IdempotencyDecision.ACQUIRED

        await store.mark_completed(
            idempotency_key,
            ttl_seconds=3600,
        )

        await store.release(idempotency_key)

        result = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert result is IdempotencyDecision.COMPLETED

    finally:
        await client.delete(redis_key)
        await client.aclose()


@pytest.mark.asyncio
async def test_redis_idempotency_applies_ttl() -> None:
    client, key_builder = _create_test_resources()

    store = RedisIdempotencyStore(
        cast(RedisScriptClient, client),
        key_builder=key_builder,
    )

    idempotency_key = "command-ttl"
    redis_key = _redis_key(
        key_builder,
        idempotency_key,
    )

    try:
        assert await client.ping() is True

        result = await store.try_acquire(
            idempotency_key,
            ttl_seconds=60,
        )

        assert result is IdempotencyDecision.ACQUIRED

        ttl = await client.ttl(redis_key)

        assert 0 < ttl <= 60

        await store.mark_completed(
            idempotency_key,
            ttl_seconds=3600,
        )

        completed_ttl = await client.ttl(redis_key)

        assert 3500 < completed_ttl <= 3600

    finally:
        await client.delete(redis_key)
        await client.aclose()
