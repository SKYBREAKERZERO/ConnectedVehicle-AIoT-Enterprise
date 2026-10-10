from __future__ import annotations

import asyncio

from connected_vehicle.remote_command.mqtt_runtime import MQTTBrokerPublisher
from connected_vehicle.remote_command.worker_runtime import remote_command_worker_runtime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.observability.logging import configure_logging
from enterprise_platform.runtime.process import run_async, run_worker, termination_signals


async def serve() -> None:
    settings = get_settings()
    configure_logging(settings)
    publisher = MQTTBrokerPublisher(settings)
    stop = asyncio.Event()
    with termination_signals(stop):
        async with remote_command_worker_runtime(settings, publisher) as runtime:
            await run_worker(
                runtime.worker.run_once,
                stop=stop,
                poll_interval=settings.worker_poll_interval_seconds,
                error_delay=settings.worker_error_delay_seconds,
                shutdown_timeout=settings.worker_shutdown_timeout_seconds,
                operation_timeout=settings.worker_operation_timeout_seconds,
            )


def main() -> None:
    run_async(serve)


if __name__ == "__main__":
    main()
