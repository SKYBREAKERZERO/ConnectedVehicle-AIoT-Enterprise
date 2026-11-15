from __future__ import annotations

import asyncio

from connected_vehicle.remote_command.outbox_runtime import remote_command_outbox_runtime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.observability.logging import configure_logging
from enterprise_platform.reliability.outbox_dispatcher import OutboxDispatchBatchResult
from enterprise_platform.reliability.policies import RetryPolicy
from enterprise_platform.runtime.process import run_async, run_worker, termination_signals


async def serve() -> None:
    settings = get_settings()
    configure_logging(settings)
    stop = asyncio.Event()
    with termination_signals(stop):
        async with remote_command_outbox_runtime(
            settings,
            RetryPolicy(
                max_attempts=settings.outbox_max_attempts,
                base_delay_seconds=1,
                max_delay_seconds=30,
            ),
        ) as dispatcher:
            await run_worker(
                dispatcher.dispatch_batch,
                stop=stop,
                poll_interval=settings.worker_poll_interval_seconds,
                error_delay=settings.worker_error_delay_seconds,
                shutdown_timeout=settings.worker_shutdown_timeout_seconds,
                operation_timeout=settings.worker_operation_timeout_seconds,
                idle_result=lambda result: (
                    isinstance(result, OutboxDispatchBatchResult) and result.claimed == 0
                ),
                max_idle_poll_interval=max(5.0, settings.worker_poll_interval_seconds),
            )


def main() -> None:
    run_async(serve)


if __name__ == "__main__":
    main()
