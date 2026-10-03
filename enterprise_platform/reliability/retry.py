from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from math import isfinite

from enterprise_platform.reliability.exceptions import RetryExhaustedError
from enterprise_platform.reliability.failure import (
    FailureClassifier,
    FailureDisposition,
)
from enterprise_platform.reliability.policies import RetryPolicy

SleepFunction = Callable[[float], Awaitable[None]]
RandomFunction = Callable[[], float]


def _normalize_operation_name(operation_name: str) -> str:
    normalized = operation_name.strip()

    if not normalized:
        raise ValueError("operation_name must not be empty.")

    return normalized


def calculate_retry_delay(
    policy: RetryPolicy,
    *,
    retry_number: int,
    random_value: float,
) -> float:
    """Calculate bounded exponential backoff with jitter."""

    if retry_number < 1:
        raise ValueError("retry_number must be at least 1.")

    if not isfinite(random_value) or not 0 <= random_value <= 1:
        raise ValueError("random_value must be a finite number between 0 and 1.")

    if policy.base_delay_seconds == 0:
        return 0.0

    exponent = min(
        retry_number - 1,
        1023,
    )

    exponential_delay = min(
        policy.base_delay_seconds * (2.0**exponent),
        policy.max_delay_seconds,
    )

    jitter_span = exponential_delay * policy.jitter_ratio
    jitter_offset = ((random_value * 2.0) - 1.0) * jitter_span

    return min(
        policy.max_delay_seconds,
        max(
            0.0,
            exponential_delay + jitter_offset,
        ),
    )


async def run_with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    operation_name: str,
    policy: RetryPolicy,
    failure_classifier: FailureClassifier,
    sleep: SleepFunction = asyncio.sleep,
    random_value: RandomFunction = random.random,
) -> T:
    """Execute an operation using bounded retry policy."""

    normalized_operation_name = _normalize_operation_name(operation_name)

    for attempt in range(
        1,
        policy.max_attempts + 1,
    ):
        try:
            return await operation()
        except Exception as exc:
            disposition = failure_classifier.classify(exc)

            if disposition is FailureDisposition.NON_RETRYABLE:
                raise

            if attempt >= policy.max_attempts:
                raise RetryExhaustedError(
                    operation_name=normalized_operation_name,
                    attempts=attempt,
                ) from exc

            delay = calculate_retry_delay(
                policy,
                retry_number=attempt,
                random_value=random_value(),
            )

            await sleep(delay)

    raise AssertionError("Retry execution terminated unexpectedly.")
