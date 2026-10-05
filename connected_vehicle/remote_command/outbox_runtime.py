from __future__ import annotations

from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
)
from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.sqs_runtime import (
    create_named_sqs_event_queue,
)
from enterprise_platform.reliability.outbox_dispatcher import (
    MappingOutboxDestinationResolver,
)


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
