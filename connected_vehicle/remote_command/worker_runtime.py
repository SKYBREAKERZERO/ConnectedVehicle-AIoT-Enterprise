from __future__ import annotations

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

    async def close(self) -> None:
        await close_redis_resources(self.redis_resources)


def create_remote_command_worker_runtime(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    publisher: RemoteCommandPublisher,
) -> RemoteCommandWorkerRuntime:
    queue = create_named_sqs_event_queue(
        settings,
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
    )

    return RemoteCommandWorkerRuntime(
        worker=worker,
        redis_resources=redis_resources,
    )
