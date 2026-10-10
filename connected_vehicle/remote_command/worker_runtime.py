from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import cast

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
)

from connected_vehicle.remote_command.dispatch_service import (
    RemoteCommandDispatchService,
)
from connected_vehicle.remote_command.event_handler import (
    RemoteCommandRequestedEventHandler,
)
from connected_vehicle.remote_command.publisher import (
    RemoteCommandPublisher,
)
from connected_vehicle.remote_command.sqs_worker import (
    RemoteCommandSQSWorker,
)

# SQLAlchemy resolves the remote_commands FK during flush even though this
# worker has no vehicle table permission and never queries that table.
from connected_vehicle.vehicle.persistence import models as _vehicle_models  # noqa: F401
from enterprise_platform.cache.client import (
    RedisResources,
    create_cache_key_builder,
    create_redis_resources,
)
from enterprise_platform.cache.lifecycle import (
    close_redis_resources,
)
from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.reliable_sqs_consumer import (
    ReliableSQSEventProcessor,
)
from enterprise_platform.messaging.sqs import SQSEventQueue
from enterprise_platform.messaging.sqs_runtime import (
    create_named_sqs_event_queue,
)
from enterprise_platform.reliability.idempotency import (
    IdempotencyService,
)
from enterprise_platform.reliability.redis_idempotency import (
    RedisIdempotencyStore,
    RedisScriptClient,
)


@dataclass(slots=True)
class RemoteCommandWorkerRuntime:
    """Runtime resources owned by the remote-command SQS worker."""

    worker: RemoteCommandSQSWorker
    redis_resources: RedisResources
    queue: SQSEventQueue | None = None

    async def close(self) -> None:
        try:
            await close_redis_resources(self.redis_resources)
        finally:
            if self.queue is not None:
                await self.queue.close()


def create_remote_command_worker_runtime(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    publisher: RemoteCommandPublisher,
) -> RemoteCommandWorkerRuntime:
    queue_settings = settings.model_copy(
        update={
            "aws_max_attempts": 1,
            "aws_read_timeout_seconds": max(
                settings.aws_read_timeout_seconds, settings.remote_command_wait_seconds + 5.0
            ),
        }
    )
    queue = create_named_sqs_event_queue(
        queue_settings,
        queue_name=settings.vehicle_command_queue_name,
    )

    redis_resources = create_redis_resources(settings)

    key_builder = create_cache_key_builder(settings)

    idempotency_store = RedisIdempotencyStore(
        cast(
            RedisScriptClient,
            redis_resources.client,
        ),
        key_builder=key_builder,
    )

    idempotency = IdempotencyService(idempotency_store)

    processor = ReliableSQSEventProcessor(
        acknowledger=queue,
        idempotency=idempotency,
    )

    dispatch_service = RemoteCommandDispatchService(
        session_factory,
        publisher,
    )

    handler = RemoteCommandRequestedEventHandler(dispatch_service)

    worker = RemoteCommandSQSWorker(
        queue=queue,
        processor=processor,
        handler=handler,
        batch_size=1,
        wait_time_seconds=settings.remote_command_wait_seconds,
    )

    return RemoteCommandWorkerRuntime(
        worker=worker,
        redis_resources=redis_resources,
        queue=queue,
    )


@asynccontextmanager
async def remote_command_worker_runtime(
    settings: Settings, publisher: RemoteCommandPublisher
) -> AsyncIterator[RemoteCommandWorkerRuntime]:
    """Production entry point owning a remote-command-only database pool."""
    from enterprise_platform.database.runtime import runtime_database_sessions

    async with runtime_database_sessions(settings, "remote-command") as sessions:
        runtime = create_remote_command_worker_runtime(settings, sessions, publisher)
        try:
            yield runtime
        finally:
            await runtime.close()
