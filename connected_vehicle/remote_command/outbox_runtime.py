from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
)
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.runtime import runtime_database_sessions
from enterprise_platform.messaging.sqs_runtime import (
    create_named_sqs_event_queue,
)
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


def create_remote_command_outbox_destinations(
    settings: Settings,
) -> MappingOutboxDestinationResolver:
    queue = create_named_sqs_event_queue(
        settings,
        queue_name=settings.vehicle_command_queue_name,
    )

    return MappingOutboxDestinationResolver(
        {
            REMOTE_COMMAND_DESTINATION: queue.send_event,
        }
    )


@asynccontextmanager
async def remote_command_outbox_runtime(
    settings: Settings,
    retry_policy: RetryPolicy,
) -> AsyncIterator[OutboxDispatcher]:
    """Production entry point owning an outbox-only database pool."""
    async with runtime_database_sessions(settings, "outbox") as sessions:
        # Persisted backoff owns retries; avoid nested SDK retry loops.
        queue_settings = settings.model_copy(update={"aws_max_attempts": 1})
        queue = create_named_sqs_event_queue(
            queue_settings, queue_name=settings.vehicle_command_queue_name
        )
        try:
            yield OutboxDispatcher(
                store=SQLAlchemyOutboxStore(sessions),
                batch_size=settings.outbox_batch_size,
                lease_seconds=settings.outbox_lease_seconds,
                retry_policy=retry_policy,
                destinations=MappingOutboxDestinationResolver(
                    {REMOTE_COMMAND_DESTINATION: queue.send_event}
                ),
            )
        finally:
            await queue.close()
