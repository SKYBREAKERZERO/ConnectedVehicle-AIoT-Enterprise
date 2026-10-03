from __future__ import annotations

import asyncio

import pytest

from enterprise_platform.reliability.exceptions import OperationTimeoutError
from enterprise_platform.reliability.policies import TimeoutPolicy
from enterprise_platform.reliability.timeout import run_with_timeout


@pytest.mark.asyncio
async def test_timeout_returns_successful_result() -> None:
    async def operation() -> str:
        return "ok"

    result = await run_with_timeout(
        operation,
        operation_name="test-operation",
        policy=TimeoutPolicy(
            timeout_seconds=1.0,
        ),
    )

    assert result == "ok"


@pytest.mark.asyncio
async def test_timeout_maps_expired_deadline() -> None:
    async def operation() -> None:
        await asyncio.sleep(0.1)

    with pytest.raises(OperationTimeoutError) as exc_info:
        await run_with_timeout(
            operation,
            operation_name="slow-operation",
            policy=TimeoutPolicy(
                timeout_seconds=0.01,
            ),
        )

    assert exc_info.value.operation_name == "slow-operation"
    assert exc_info.value.timeout_seconds == 0.01


@pytest.mark.asyncio
async def test_timeout_does_not_remap_dependency_timeout() -> None:
    async def operation() -> None:
        raise TimeoutError("dependency timed out")

    with pytest.raises(
        TimeoutError,
        match="dependency timed out",
    ):
        await run_with_timeout(
            operation,
            operation_name="dependency-operation",
            policy=TimeoutPolicy(
                timeout_seconds=1.0,
            ),
        )


@pytest.mark.asyncio
async def test_timeout_rejects_empty_operation_name() -> None:
    async def operation() -> str:
        return "unused"

    with pytest.raises(ValueError):
        await run_with_timeout(
            operation,
            operation_name="   ",
            policy=TimeoutPolicy(
                timeout_seconds=1.0,
            ),
        )
