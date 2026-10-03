from __future__ import annotations

import math

import pytest

from enterprise_platform.reliability.exceptions import RetryExhaustedError
from enterprise_platform.reliability.failure import (
    ExceptionTypeFailureClassifier,
)
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.reliability.retry import (
    calculate_retry_delay,
    run_with_retry,
)


def test_retry_delay_uses_exponential_backoff() -> None:
    policy = RetryPolicy(
        max_attempts=5,
        base_delay_seconds=1.0,
        max_delay_seconds=10.0,
        jitter_ratio=0.0,
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=1,
            random_value=0.5,
        )
        == 1.0
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=2,
            random_value=0.5,
        )
        == 2.0
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=3,
            random_value=0.5,
        )
        == 4.0
    )


def test_retry_delay_is_bounded_by_max_delay() -> None:
    policy = RetryPolicy(
        max_attempts=5,
        base_delay_seconds=2.0,
        max_delay_seconds=3.0,
        jitter_ratio=0.0,
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=5,
            random_value=0.5,
        )
        == 3.0
    )


def test_retry_delay_applies_symmetric_jitter() -> None:
    policy = RetryPolicy(
        base_delay_seconds=5.0,
        max_delay_seconds=10.0,
        jitter_ratio=0.2,
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=1,
            random_value=0.0,
        )
        == 4.0
    )

    assert (
        calculate_retry_delay(
            policy,
            retry_number=1,
            random_value=1.0,
        )
        == 6.0
    )


@pytest.mark.parametrize(
    "random_value",
    [
        -0.1,
        1.1,
        math.inf,
        math.nan,
    ],
)
def test_retry_delay_rejects_invalid_random_value(
    random_value: float,
) -> None:
    with pytest.raises(ValueError):
        calculate_retry_delay(
            RetryPolicy(),
            retry_number=1,
            random_value=random_value,
        )


def test_retry_delay_rejects_invalid_retry_number() -> None:
    with pytest.raises(ValueError):
        calculate_retry_delay(
            RetryPolicy(),
            retry_number=0,
            random_value=0.5,
        )


@pytest.mark.asyncio
async def test_retry_returns_first_attempt_success() -> None:
    calls = 0

    async def operation() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    classifier = ExceptionTypeFailureClassifier((RuntimeError,))

    result = await run_with_retry(
        operation,
        operation_name="first-success",
        policy=RetryPolicy(),
        failure_classifier=classifier,
    )

    assert result == "ok"
    assert calls == 1


@pytest.mark.asyncio
async def test_retry_recovers_from_retryable_failure() -> None:
    calls = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal calls
        calls += 1

        if calls < 3:
            raise RuntimeError("temporary")

        return "ok"

    async def fake_sleep(
        delay: float,
    ) -> None:
        delays.append(delay)

    classifier = ExceptionTypeFailureClassifier((RuntimeError,))

    result = await run_with_retry(
        operation,
        operation_name="retryable-operation",
        policy=RetryPolicy(
            max_attempts=3,
            base_delay_seconds=1.0,
            max_delay_seconds=10.0,
            jitter_ratio=0.0,
        ),
        failure_classifier=classifier,
        sleep=fake_sleep,
        random_value=lambda: 0.5,
    )

    assert result == "ok"
    assert calls == 3
    assert delays == [
        1.0,
        2.0,
    ]


@pytest.mark.asyncio
async def test_retry_does_not_retry_non_retryable_failure() -> None:
    calls = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal calls
        calls += 1
        raise ValueError("permanent")

    async def fake_sleep(
        delay: float,
    ) -> None:
        delays.append(delay)

    classifier = ExceptionTypeFailureClassifier((RuntimeError,))

    with pytest.raises(
        ValueError,
        match="permanent",
    ):
        await run_with_retry(
            operation,
            operation_name="permanent-operation",
            policy=RetryPolicy(),
            failure_classifier=classifier,
            sleep=fake_sleep,
        )

    assert calls == 1
    assert delays == []


@pytest.mark.asyncio
async def test_retry_raises_after_attempts_exhausted() -> None:
    calls = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("temporary")

    async def fake_sleep(
        delay: float,
    ) -> None:
        delays.append(delay)

    classifier = ExceptionTypeFailureClassifier((RuntimeError,))

    with pytest.raises(RetryExhaustedError) as exc_info:
        await run_with_retry(
            operation,
            operation_name="unstable-operation",
            policy=RetryPolicy(
                max_attempts=3,
                base_delay_seconds=1.0,
                max_delay_seconds=10.0,
                jitter_ratio=0.0,
            ),
            failure_classifier=classifier,
            sleep=fake_sleep,
            random_value=lambda: 0.5,
        )

    assert exc_info.value.operation_name == "unstable-operation"
    assert exc_info.value.attempts == 3
    assert calls == 3
    assert delays == [
        1.0,
        2.0,
    ]
