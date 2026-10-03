from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable

from enterprise_platform.reliability.failure import FailureClassifier
from enterprise_platform.reliability.policies import ReliabilityPolicy
from enterprise_platform.reliability.retry import run_with_retry
from enterprise_platform.reliability.timeout import run_with_timeout

SleepFunction = Callable[[float], Awaitable[None]]
RandomFunction = Callable[[], float]


class ReliabilityExecutor:
    """Executes operations according to a unified reliability policy."""

    def __init__(
        self,
        *,
        sleep: SleepFunction = asyncio.sleep,
        random_value: RandomFunction = random.random,
    ) -> None:
        self._sleep = sleep
        self._random_value = random_value

    async def execute[T](
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        operation_name: str,
        policy: ReliabilityPolicy,
        failure_classifier: FailureClassifier | None = None,
    ) -> T:
        normalized_operation_name = operation_name.strip()

        if not normalized_operation_name:
            raise ValueError("operation_name must not be empty.")

        if policy.retry is not None and failure_classifier is None:
            raise ValueError("failure_classifier is required when retry is enabled.")

        async def execute_policy() -> T:
            if policy.retry is None:
                return await operation()

            assert failure_classifier is not None

            return await run_with_retry(
                operation,
                operation_name=normalized_operation_name,
                policy=policy.retry,
                failure_classifier=failure_classifier,
                sleep=self._sleep,
                random_value=self._random_value,
            )

        return await run_with_timeout(
            execute_policy,
            operation_name=normalized_operation_name,
            policy=policy.timeout,
        )
