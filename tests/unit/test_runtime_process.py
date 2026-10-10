from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress

import pytest

from enterprise_platform.runtime.process import run_worker


async def worker(
    operation: Callable[[], Awaitable[object]],
    stop: asyncio.Event,
    *,
    shutdown: float = 0.1,
    deadline: float = 1,
) -> None:
    await run_worker(
        operation,
        stop=stop,
        poll_interval=0.001,
        error_delay=0.001,
        shutdown_timeout=shutdown,
        operation_timeout=deadline,
    )


async def test_stop_drains_current_batch_and_does_not_poll_again() -> None:
    stop, started, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def operation() -> None:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()

    task = asyncio.create_task(worker(operation, stop))
    await started.wait()
    stop.set()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    await task
    assert calls == 1


async def test_drain_deadline_cancels_inflight_work() -> None:
    stop, started, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def operation() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    task = asyncio.create_task(worker(operation, stop, shutdown=0.01))
    await started.wait()
    stop.set()
    await asyncio.wait_for(task, timeout=1)
    assert cancelled.is_set()


@pytest.mark.parametrize("failure", ["error", "timeout"])
async def test_transient_failure_or_timeout_does_not_kill_poller(failure: str) -> None:
    stop = asyncio.Event()
    calls = 0

    async def operation() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            if failure == "error":
                raise ConnectionError("transient")
            await asyncio.Event().wait()
        stop.set()

    await asyncio.wait_for(worker(operation, stop, deadline=0.01), timeout=1)
    assert calls == 2


async def test_parent_cancellation_leaves_no_batch_task_running() -> None:
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def operation() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    task = asyncio.create_task(worker(operation, asyncio.Event()))
    await started.wait()
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
