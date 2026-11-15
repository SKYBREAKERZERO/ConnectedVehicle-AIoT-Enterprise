"""Atomic, shared Redis retry budget for Outbox worker fleets.

The budget governs *retry sends*, not first attempts or failed-but-unattempted
claims. Redis TIME is the only clock. An unavailable Redis fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from inspect import isawaitable
from math import isfinite
from typing import Protocol


class RedisScriptEvaluator(Protocol):
    def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object: ...


@dataclass(frozen=True, slots=True)
class RetryBudgetPolicy:
    rate_per_second: float = 20.0
    burst: int = 40
    defer_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isfinite(self.rate_per_second) or not 0 < self.rate_per_second <= 10_000:
            raise ValueError("Retry budget rate must be finite and in (0, 10000]")
        if not 1 <= self.burst <= 10_000:
            raise ValueError("Retry budget burst must be between 1 and 10000")
        if not isfinite(self.defer_seconds) or not 0 < self.defer_seconds <= 300:
            raise ValueError("Retry budget deferral must be finite and in (0, 300]")


class RetryBudget(Protocol):
    """Shared permit contract, allowing deterministic fault-injection tests."""

    policy: RetryBudgetPolicy

    async def acquire(self, requested: int = 1) -> int: ...


_RETRY_BUDGET_SCRIPT = """
local now_parts = redis.call('TIME')
local now_ms = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
if not rate or not capacity or not requested or rate <= 0 or capacity < 1
   or requested < 1 or requested > 1000 then
    return redis.error_reply('invalid retry budget arguments')
end
local last_ms = tonumber(redis.call('HMGET', KEYS[1], 'last_ms')[1]) or now_ms
local previous = tonumber(redis.call('HMGET', KEYS[1], 'tokens')[1]) or capacity
local elapsed = math.max(0, now_ms - last_ms)
local tokens = math.min(capacity, previous + elapsed * rate / 1000)
local granted = math.min(requested, math.floor(tokens))
redis.call('HSET', KEYS[1], 'tokens', tokens - granted, 'last_ms', now_ms)
local ttl_ms = math.max(1000, math.ceil(2000 * capacity / rate))
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return granted
"""


class RedisRetryBudget:
    """All replicas sharing a Redis key share the same atomic token allowance."""

    def __init__(
        self, client: RedisScriptEvaluator, *, key: str, policy: RetryBudgetPolicy
    ) -> None:
        if not key or key.strip() != key or any(ord(char) < 33 for char in key):
            raise ValueError("Invalid retry budget key")
        self._client = client
        self._key = key
        self.policy = policy

    async def acquire(self, requested: int = 1) -> int:
        if not 1 <= requested <= 1000:
            raise ValueError("Retry budget request must be between 1 and 1000")
        response = self._client.eval(
            _RETRY_BUDGET_SCRIPT,
            1,
            self._key,
            str(self.policy.rate_per_second),
            str(self.policy.burst),
            str(requested),
        )
        value = await response if isawaitable(response) else response
        if type(value) is not int or not 0 <= value <= min(requested, self.policy.burst):
            raise RuntimeError("Invalid retry budget grant response")
        return value
