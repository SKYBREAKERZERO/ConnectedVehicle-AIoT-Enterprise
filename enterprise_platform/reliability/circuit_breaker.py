"""Bounded shared circuit state with Redis-atomic half-open probe ownership."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import uuid4


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True)
class CircuitPolicy:
    failure_threshold: int = 5
    open_seconds: int = 30
    probe_lease_seconds: int = 10
    successes_to_close: int = 2

    def __post_init__(self) -> None:
        if min(
            self.failure_threshold,
            self.open_seconds,
            self.probe_lease_seconds,
            self.successes_to_close,
        ) < 1:
            raise ValueError("Circuit policy values must be positive")


@dataclass(frozen=True, slots=True)
class CircuitPermit:
    allowed: bool
    token: str = ""


class CircuitGate(Protocol):
    async def acquire(self) -> CircuitPermit: ...

    async def success(self, permit: CircuitPermit) -> None: ...

    async def failure(self, permit: CircuitPermit) -> None: ...

    async def release(self, permit: CircuitPermit) -> None: ...


class InMemoryCircuitBreaker:
    """Deterministic state machine for unit tests and single-process callers."""

    def __init__(
        self, policy: CircuitPolicy, *, clock: Callable[[], float]
    ) -> None:
        self.policy = policy
        self.clock = clock
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.successes = 0
        self.open_until = 0.0
        self.probe_token = ""
        self.probe_until = 0.0
        self._mutex = asyncio.Lock()

    async def acquire(self) -> CircuitPermit:
        async with self._mutex:
            now = self.clock()
            if self.state is CircuitState.OPEN:
                if now < self.open_until:
                    return CircuitPermit(False)
                self.state = CircuitState.HALF_OPEN
            if self.state is CircuitState.HALF_OPEN:
                if self.probe_token and now < self.probe_until:
                    return CircuitPermit(False)
                self.probe_token = uuid4().hex
                self.probe_until = now + self.policy.probe_lease_seconds
                return CircuitPermit(True, self.probe_token)
            return CircuitPermit(True)

    async def success(self, permit: CircuitPermit) -> None:
        async with self._mutex:
            if not permit.allowed:
                return
            if self.state is CircuitState.CLOSED:
                self.failures = 0
            elif (
                self.state is CircuitState.HALF_OPEN
                and permit.token == self.probe_token
                and self.clock() < self.probe_until
            ):
                self.successes += 1
                self.probe_token = ""
                if self.successes >= self.policy.successes_to_close:
                    self.state = CircuitState.CLOSED
                    self.failures = 0
                    self.successes = 0

    async def failure(self, permit: CircuitPermit) -> None:
        async with self._mutex:
            if not permit.allowed:
                return
            if self.state is CircuitState.HALF_OPEN:
                if (
                    not permit.token
                    or permit.token != self.probe_token
                    or self.clock() >= self.probe_until
                ):
                    return
                self._open()
            elif self.state is CircuitState.CLOSED:
                self.failures += 1
                if self.failures >= self.policy.failure_threshold:
                    self._open()

    async def release(self, permit: CircuitPermit) -> None:
        async with self._mutex:
            if self.state is CircuitState.HALF_OPEN and permit.token == self.probe_token:
                self.probe_token = ""

    def _open(self) -> None:
        self.state = CircuitState.OPEN
        self.open_until = self.clock() + self.policy.open_seconds
        self.probe_token = ""
        self.successes = 0


class RedisEval(Protocol):
    async def eval(self, script: str, numkeys: int, *args: object) -> object: ...


# Redis TIME is authoritative: client clock skew cannot create extra probe permits.
# A probe token is fenced at the shared state boundary. Missing Redis fails closed.
_REDIS_SCRIPT = """
local action = ARGV[1]
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local state = redis.call('HGET', KEYS[1], 'state') or 'closed'
local token = redis.call('HGET', KEYS[1], 'probe') or ''
if action == 'acquire' then
    if state == 'open' then
        local until_ms = tonumber(redis.call('HGET', KEYS[1], 'until_ms') or '0')
        if now < until_ms then return 'blocked' end
        state = 'half_open'
        redis.call('HSET', KEYS[1], 'state', state, 'successes', 0, 'probe', '')
    end
    if state == 'half_open' then
        local expiry = tonumber(redis.call('HGET', KEYS[1], 'probe_until') or '0')
        if token ~= '' and now < expiry then return 'blocked' end
        redis.call('HSET', KEYS[1], 'probe', ARGV[2],
                   'probe_until', now + tonumber(ARGV[5]))
        return 'probe'
    end
    return 'normal'
end
if action == 'release' then
    if state == 'half_open' and token ~= '' and token == ARGV[2] then
        redis.call('HSET', KEYS[1], 'probe', '')
    end
    return 'ok'
end
if action == 'success' then
    if state == 'closed' then
        redis.call('HSET', KEYS[1], 'failures', 0)
    elseif state == 'half_open' and token ~= '' and token == ARGV[2] then
        local expiry = tonumber(redis.call('HGET', KEYS[1], 'probe_until') or '0')
        if now >= expiry then return 'stale' end
        local successes = tonumber(redis.call('HGET', KEYS[1], 'successes') or '0') + 1
        if successes >= tonumber(ARGV[6]) then
            redis.call('HSET', KEYS[1], 'state', 'closed', 'failures', 0,
                       'successes', 0, 'probe', '')
        else
            redis.call('HSET', KEYS[1], 'successes', successes, 'probe', '')
        end
    end
    return 'ok'
end
if action == 'failure' then
    if state == 'half_open' and token ~= '' and token == ARGV[2] then
        local expiry = tonumber(redis.call('HGET', KEYS[1], 'probe_until') or '0')
        if now >= expiry then return 'stale' end
        redis.call('HSET', KEYS[1], 'state', 'open', 'until_ms',
                   now + tonumber(ARGV[4]), 'failures', tonumber(ARGV[3]),
                   'successes', 0, 'probe', '')
    elseif state == 'closed' then
        local failures = redis.call('HINCRBY', KEYS[1], 'failures', 1)
        if failures >= tonumber(ARGV[3]) then
            redis.call('HSET', KEYS[1], 'state', 'open', 'until_ms',
                       now + tonumber(ARGV[4]), 'successes', 0, 'probe', '')
        end
    end
    return 'ok'
end
return redis.error_reply('invalid circuit operation')
"""


class RedisCircuitBreaker:
    """Shared breaker by logical destination; all decisions are Redis-atomic."""

    def __init__(
        self, client: RedisEval, *, key: str, policy: CircuitPolicy
    ) -> None:
        if not key or key.strip() != key or any(ord(c) < 33 for c in key):
            raise ValueError("Invalid circuit key")
        self.client = client
        self.key = key
        self.policy = policy

    async def _act(self, action: str, token: str = "") -> str:
        value = await self.client.eval(
            _REDIS_SCRIPT, 1, self.key, action, token,
            self.policy.failure_threshold,
            self.policy.open_seconds * 1000,
            self.policy.probe_lease_seconds * 1000,
            self.policy.successes_to_close,
        )
        if isinstance(value, bytes):
            return value.decode("utf-8")
        if not isinstance(value, str):
            raise RuntimeError("Invalid Redis circuit response")
        return value

    async def acquire(self) -> CircuitPermit:
        token = uuid4().hex
        result = await self._act("acquire", token)
        if result == "blocked":
            return CircuitPermit(False)
        if result == "probe":
            return CircuitPermit(True, token)
        if result == "normal":
            return CircuitPermit(True)
        raise RuntimeError("Invalid circuit acquisition result")

    async def success(self, permit: CircuitPermit) -> None:
        if permit.allowed:
            await self._act("success", permit.token)

    async def failure(self, permit: CircuitPermit) -> None:
        if permit.allowed:
            await self._act("failure", permit.token)

    async def release(self, permit: CircuitPermit) -> None:
        if permit.allowed and permit.token:
            await self._act("release", permit.token)
