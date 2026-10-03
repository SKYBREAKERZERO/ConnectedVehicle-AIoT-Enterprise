from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from enterprise_platform.reliability.exceptions import OperationTimeoutError
from enterprise_platform.reliability.policies import TimeoutPolicy


def _normalize_operation_name(operation_name: str) -> str:
    normalized = operation_name.strip()

    if not normalized:
        raise ValueError("operation_name must not be empty.")

    return normalized


async def run_with_timeout[T](
    operation: Callable[[], Awaitable[T]],
    *,
    operation_name: str,
    policy: TimeoutPolicy,
) -> T:
    """Execute one operation within an application-level deadline."""

    normalized_operation_name = _normalize_operation_name(operation_name)

    timeout_context = asyncio.timeout(
        policy.timeout_seconds,
    )

    try:
        async with timeout_context:
            return await operation()
    except TimeoutError as exc:
        if timeout_context.expired():
            raise OperationTimeoutError(
                operation_name=normalized_operation_name,
                timeout_seconds=policy.timeout_seconds,
            ) from exc

        raise
