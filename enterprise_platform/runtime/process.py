from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from contextlib import contextmanager, suppress
from typing import Any

logger = logging.getLogger(__name__)


@contextmanager
def termination_signals(stop: asyncio.Event) -> Iterator[None]:
    """Also works on Windows, where add_signal_handler is unavailable."""
    loop = asyncio.get_running_loop()
    previous = {}
    signals = [signal.SIGINT, signal.SIGTERM]
    if sys.platform == "win32":
        signals.append(signal.SIGBREAK)
    for number in signals:
        previous[number] = signal.getsignal(number)
        signal.signal(number, lambda *_: loop.call_soon_threadsafe(stop.set))
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


async def run_worker(
    operation: Callable[[], Awaitable[object]],
    *,
    stop: asyncio.Event,
    poll_interval: float,
    error_delay: float,
    shutdown_timeout: float,
    operation_timeout: float,
) -> None:
    """Stop polling on termination, drain once, then cancel without ACK."""

    async def one_batch() -> object:
        async with asyncio.timeout(operation_timeout):
            return await operation()

    while not stop.is_set():
        batch = asyncio.create_task(one_batch())
        stopping = asyncio.create_task(stop.wait())
        delay = poll_interval
        try:
            done, _ = await asyncio.wait({batch, stopping}, return_when=asyncio.FIRST_COMPLETED)
            if stopping in done:
                try:
                    await asyncio.wait_for(asyncio.shield(batch), timeout=shutdown_timeout)
                except TimeoutError:
                    logger.warning("worker_drain_timeout")
                    batch.cancel()
                    with suppress(asyncio.CancelledError):
                        await batch
                except Exception as exc:
                    logger.warning("worker_drain_failed: %s", type(exc).__name__)
                break
            try:
                result = await batch
                logger.info("worker_batch: %s", result)
            except Exception as exc:
                # Do not log broker URLs, payloads, passwords or raw SDK errors.
                logger.warning("worker_batch_failed: %s", type(exc).__name__)
                delay = error_delay
        finally:
            stopping.cancel()
            if not batch.done():
                batch.cancel()
            await asyncio.gather(batch, stopping, return_exceptions=True)
        if not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=delay)
    logger.info("worker_stopped")


def run_async(main: Callable[[], Coroutine[Any, Any, None]]) -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
