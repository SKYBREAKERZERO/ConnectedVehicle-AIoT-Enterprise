"""Circuit state contract: failure threshold, OPEN, and half-open ownership."""

import pytest

from enterprise_platform.reliability.circuit_breaker import (
    CircuitPolicy,
    CircuitState,
    InMemoryCircuitBreaker,
)


@pytest.mark.asyncio
async def test_cb001_failure_threshold_opens() -> None:
    now = [10.0]
    breaker = InMemoryCircuitBreaker(
        CircuitPolicy(failure_threshold=2), clock=lambda: now[0]
    )
    first = await breaker.acquire()
    await breaker.failure(first)
    assert breaker.state is CircuitState.CLOSED
    second = await breaker.acquire()
    await breaker.failure(second)
    assert breaker.state is CircuitState.OPEN
    assert not (await breaker.acquire()).allowed


@pytest.mark.asyncio
async def test_cb002_open_short_circuits() -> None:
    now = [10.0]
    breaker = InMemoryCircuitBreaker(
        CircuitPolicy(failure_threshold=1, open_seconds=30), clock=lambda: now[0]
    )
    await breaker.failure(await breaker.acquire())
    assert breaker.state is CircuitState.OPEN
    for _ in range(20):
        assert not (await breaker.acquire()).allowed
    assert breaker.failures == 1
    now[0] += 29.0
    assert not (await breaker.acquire()).allowed


@pytest.mark.asyncio
async def test_cb003_half_open_single_local_probe() -> None:
    now = [10.0]
    breaker = InMemoryCircuitBreaker(
        CircuitPolicy(
            failure_threshold=1, open_seconds=1, probe_lease_seconds=5
        ),
        clock=lambda: now[0],
    )
    await breaker.failure(await breaker.acquire())
    now[0] += 1.1
    probe = await breaker.acquire()
    assert probe.allowed and probe.token
    assert breaker.state is CircuitState.HALF_OPEN
    assert not (await breaker.acquire()).allowed
    await breaker.release(probe)
    another = await breaker.acquire()
    assert another.allowed and another.token != probe.token


@pytest.mark.asyncio
async def test_cb004_half_open_success_closes() -> None:
    now = [10.0]
    breaker = InMemoryCircuitBreaker(
        CircuitPolicy(
            failure_threshold=1, open_seconds=1, successes_to_close=2
        ),
        clock=lambda: now[0],
    )
    await breaker.failure(await breaker.acquire())
    now[0] += 1.1
    first = await breaker.acquire()
    await breaker.success(first)
    assert breaker.state is CircuitState.HALF_OPEN
    second = await breaker.acquire()
    await breaker.success(second)
    assert breaker.state is CircuitState.CLOSED
    assert (await breaker.acquire()).allowed
