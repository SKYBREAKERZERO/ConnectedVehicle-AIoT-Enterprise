from __future__ import annotations

import asyncio

import pytest

from enterprise_platform.reliability.exceptions import (
    OperationTimeoutError,
)
from enterprise_platform.reliability.executor import ReliabilityExecutor
from enterprise_platform.reliability.failure import (
    ExceptionTypeFailureClassifier,
)
from enterprise_platform.reliability.policies import (
    ReliabilityPolicy,
    RetryPolicy,
    TimeoutPolicy,
)


@pytest.mark.asyncio
async def test_executor_runs_without_retry_policy() -> None:
    calls = 0

    async def operation() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    executor = ReliabilityExecutor()

    result = await executor.execute(
        operation,
        operation_name="simple-operation",
        policy=ReliabilityPolicy(
            timeout=TimeoutPolicy(
                timeout_seconds=1.0,
            )
        ),
    )

    assert result == "ok"
    assert calls == 1


@pytest.mark.asyncio
async def test_executor_applies_retry_policy() -> None:
    calls = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal calls
        calls += 1

        if calls == 1:
            raise ConnectionError("temporary")

        return "ok"

    async def fake_sleep(
        delay: float,
    ) -> None:
        delays.append(delay)

    executor = ReliabilityExecutor(
        sleep=fake_sleep,
        random_value=lambda: 0.5,
    )

    classifier = ExceptionTypeFailureClassifier((ConnectionError,))

    result = await executor.execute(
        operation,
        operation_name="retry-operation",
        policy=ReliabilityPolicy(
            timeout=TimeoutPolicy(
                timeout_seconds=1.0,
            ),
            retry=RetryPolicy(
                max_attempts=3,
                base_delay_seconds=0.1,
                max_delay_seconds=1.0,
                jitter_ratio=0.0,
            ),
        ),
        failure_classifier=classifier,
    )

    assert result == "ok"
    assert calls == 2
    assert delays == [
        0.1,
    ]


@pytest.mark.asyncio
async def test_executor_requires_classifier_when_retry_enabled() -> None:
    async def operation() -> str:
        return "unused"

    executor = ReliabilityExecutor()

    with pytest.raises(
        ValueError,
        match="failure_classifier",
    ):
        await executor.execute(
            operation,
            operation_name="retry-operation",
            policy=ReliabilityPolicy(
                timeout=TimeoutPolicy(
                    timeout_seconds=1.0,
                ),
                retry=RetryPolicy(),
            ),
        )


@pytest.mark.asyncio
async def test_executor_overall_timeout_bounds_operation() -> None:
    async def operation() -> str:
        await asyncio.sleep(0.1)
        return "too-late"

    executor = ReliabilityExecutor()

    with pytest.raises(OperationTimeoutError):
        await executor.execute(
            operation,
            operation_name="bounded-operation",
            policy=ReliabilityPolicy(
                timeout=TimeoutPolicy(
                    timeout_seconds=0.01,
                )
            ),
        )


@pytest.mark.asyncio
async def test_executor_timeout_includes_retry_backoff() -> None:
    async def operation() -> str:
        raise ConnectionError("temporary")

    executor = ReliabilityExecutor()

    classifier = ExceptionTypeFailureClassifier((ConnectionError,))

    with pytest.raises(OperationTimeoutError):
        await executor.execute(
            operation,
            operation_name="retry-with-deadline",
            policy=ReliabilityPolicy(
                timeout=TimeoutPolicy(
                    timeout_seconds=0.01,
                ),
                retry=RetryPolicy(
                    max_attempts=3,
                    base_delay_seconds=0.1,
                    max_delay_seconds=0.1,
                    jitter_ratio=0.0,
                ),
            ),
            failure_classifier=classifier,
        )


@pytest.mark.asyncio
async def test_executor_rejects_empty_operation_name() -> None:
    async def operation() -> str:
        return "unused"

    executor = ReliabilityExecutor()

    with pytest.raises(ValueError):
        await executor.execute(
            operation,
            operation_name="   ",
            policy=ReliabilityPolicy(
                timeout=TimeoutPolicy(
                    timeout_seconds=1.0,
                )
            ),
        )
