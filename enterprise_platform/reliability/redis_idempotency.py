from __future__ import annotations

from hashlib import sha256
from typing import Protocol

from redis.exceptions import RedisError

from enterprise_platform.cache.client import CacheKeyBuilder
from enterprise_platform.reliability.exceptions import (
    IdempotencyStateError,
    IdempotencyStoreError,
)
from enterprise_platform.reliability.idempotency import (
    IdempotencyDecision,
    IdempotencyStore,
)


class RedisScriptClient(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> object: ...


_ACQUIRE_SCRIPT = """
local current = redis.call("GET", KEYS[1])

if current == "in_progress" then
    return "in_progress"
end

if current == "completed" then
    return "completed"
end

if current then
    return "invalid"
end

redis.call(
    "SET",
    KEYS[1],
    "in_progress",
    "EX",
    ARGV[1]
)

return "acquired"
"""


_COMPLETE_SCRIPT = """
local current = redis.call("GET", KEYS[1])

if current == "in_progress" then
    redis.call(
        "SET",
        KEYS[1],
        "completed",
        "EX",
        ARGV[1]
    )
    return "completed"
end

if current == "completed" then
    redis.call(
        "EXPIRE",
        KEYS[1],
        ARGV[1]
    )
    return "completed"
end

return "missing"
"""


_RELEASE_SCRIPT = """
local current = redis.call("GET", KEYS[1])

if current == "in_progress" then
    return redis.call(
        "DEL",
        KEYS[1]
    )
end

return 0
"""


def _decode_script_result(
    value: object,
) -> str:
    if isinstance(value, str):
        return value

    if isinstance(value, bytes):
        return value.decode("utf-8")

    raise IdempotencyStoreError()


class RedisIdempotencyStore(IdempotencyStore):
    """Redis-backed atomic idempotency state store."""

    def __init__(
        self,
        client: RedisScriptClient,
        *,
        key_builder: CacheKeyBuilder,
    ) -> None:
        self._client = client
        self._key_builder = key_builder

    def _build_key(
        self,
        key: str,
    ) -> str:
        digest = sha256(key.encode("utf-8")).hexdigest()

        return self._key_builder.build(
            "idempotency",
            digest,
        )

    async def try_acquire(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> IdempotencyDecision:
        redis_key = self._build_key(key)

        try:
            result = await self._client.eval(
                _ACQUIRE_SCRIPT,
                1,
                redis_key,
                ttl_seconds,
            )
        except RedisError as exc:
            raise IdempotencyStoreError() from exc

        state = _decode_script_result(result)

        if state == "acquired":
            return IdempotencyDecision.ACQUIRED

        if state == "in_progress":
            return IdempotencyDecision.IN_PROGRESS

        if state == "completed":
            return IdempotencyDecision.COMPLETED

        raise IdempotencyStateError()

    async def mark_completed(
        self,
        key: str,
        *,
        ttl_seconds: int,
    ) -> None:
        redis_key = self._build_key(key)

        try:
            result = await self._client.eval(
                _COMPLETE_SCRIPT,
                1,
                redis_key,
                ttl_seconds,
            )
        except RedisError as exc:
            raise IdempotencyStoreError() from exc

        state = _decode_script_result(result)

        if state == "completed":
            return

        raise IdempotencyStateError()

    async def release(
        self,
        key: str,
    ) -> None:
        redis_key = self._build_key(key)

        try:
            await self._client.eval(
                _RELEASE_SCRIPT,
                1,
                redis_key,
            )
        except RedisError as exc:
            raise IdempotencyStoreError() from exc
