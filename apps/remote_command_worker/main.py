from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from contextlib import suppress
from typing import Protocol, cast

from aiomqtt import Client

from connected_vehicle.remote_command.aws_iot_publisher import create_aws_iot_publisher
from connected_vehicle.remote_command.mqtt_publisher import MQTTRemoteCommandPublisher
from connected_vehicle.remote_command.publisher import RemoteCommandPublisher
from connected_vehicle.remote_command.sqs_worker import RemoteCommandWorkerBatchResult
from connected_vehicle.remote_command.worker_runtime import remote_command_worker_runtime
from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings, get_settings
from enterprise_platform.reliability.ecs_task_protection import protect_worker_batch

logger = logging.getLogger(__name__)


class CommandWorker(Protocol):
    async def run_once(self) -> RemoteCommandWorkerBatchResult: ...


def resolve_worker(runtime: object) -> CommandWorker:
    candidate = getattr(runtime, "worker", runtime)
    if not callable(getattr(candidate, "run_once", None)):
        raise TypeError("Remote command runtime must expose run_once().")
    return cast(CommandWorker, candidate)


def _mqtt_port() -> int:
    port = int(os.environ.get("MQTT_PORT", "1883"))
    if not 1 <= port <= 65535:
        raise ValueError("MQTT_PORT must be between 1 and 65535.")
    return port


def _install_shutdown_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Signal registration is unavailable on some Windows event loops.
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)


async def _serve(
    settings: Settings, publisher: RemoteCommandPublisher, stop: asyncio.Event
) -> None:
    # DatabaseRuntime.REMOTE_COMMAND owns an isolated pool, tenant binding and grants.
    async with remote_command_worker_runtime(settings, publisher) as resource:
        worker = resolve_worker(resource)
        logger.info("Remote command worker started")
        while not stop.is_set():
            async with protect_worker_batch(settings):
                batch = await worker.run_once()
            if batch.failed:
                # Failed SQS messages remain unacknowledged for redelivery.
                raise RuntimeError("Remote command batch failed; restart runtime")
            if batch.received:
                logger.info(
                    "Remote command batch received=%d processed=%d duplicates=%d",
                    batch.received,
                    batch.processed,
                    batch.duplicates,
                )


async def run(settings: Settings | None = None) -> None:
    settings = settings if settings is not None else get_settings()
    stop = asyncio.Event()
    _install_shutdown_handlers(stop)

    if settings.cloud_runtime is CloudRuntime.AWS:
        if settings.app_env is not AppEnvironment.STAGING:
            raise RuntimeError("AWS IoT Core remote worker is staging-only until release review")
        # Validate the exact ATS endpoint and IAM-signed client BEFORE SQS polling.
        await _serve(settings, create_aws_iot_publisher(settings), stop)
    elif settings.cloud_runtime is CloudRuntime.LOCALSTACK:
        # Mosquitto is an intentionally local-only adapter; never use it on AWS.
        host = os.environ.get("MQTT_HOST", "127.0.0.1").strip()
        if not host:
            raise ValueError("MQTT_HOST must not be empty")
        port = _mqtt_port()
        async with Client(hostname=host, port=port) as mqtt:
            await _serve(settings, MQTTRemoteCommandPublisher(mqtt), stop)
    else:
        raise RuntimeError("Unsupported remote command transport")
    logger.info("Remote command worker stopped")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    if sys.platform == "win32":
        # aiomqtt uses loop.add_reader(), unavailable in Windows Proactor loop.
        from asyncio import WindowsSelectorEventLoopPolicy

        asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
    with suppress(KeyboardInterrupt):
        asyncio.run(run())


if __name__ == "__main__":
    main()
