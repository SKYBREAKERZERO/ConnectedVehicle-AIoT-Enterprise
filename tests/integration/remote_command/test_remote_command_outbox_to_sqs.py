from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from connected_vehicle.remote_command import (
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
)
from connected_vehicle.remote_command.outbox_runtime import (
    create_remote_command_outbox_destinations,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.remote_command.service import (
    IssueRemoteCommandService,
)
from connected_vehicle.vehicle import (
    VIN,
    Vehicle,
    VehicleId,
    VehicleStatus,
)
from connected_vehicle.vehicle.persistence.models import VehicleModel
from connected_vehicle.vehicle.persistence.repository import (
    SQLAlchemyVehicleRepository,
)
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.sqs import SQSEventQueue
from enterprise_platform.messaging.sqs_runtime import (
    create_named_sqs_event_queue,
)
from enterprise_platform.reliability.outbox_dispatcher import (
    OutboxDispatcher,
)
from enterprise_platform.reliability.policies import RetryPolicy


def create_active_vehicle() -> Vehicle:
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=VIN(uuid4().hex[:17].upper()),
        tenant_id="tenant-outbox-sqs",
    )

    return vehicle.transition_to(VehicleStatus.ACTIVE)


def create_retry_policy() -> RetryPolicy:
    return RetryPolicy(
        max_attempts=5,
        base_delay_seconds=1.0,
        max_delay_seconds=30.0,
        jitter_ratio=0.0,
    )


async def drain_queue(
    queue: SQSEventQueue,
) -> None:
    for _ in range(10):
        messages = await queue.receive_events(
            max_messages=10,
            wait_time_seconds=0,
        )

        if not messages:
            return

        for message in messages:
            await queue.delete_message(message.receipt_handle)

    raise AssertionError("Vehicle command queue could not be drained.")


@pytest.mark.asyncio
async def test_remote_command_outbox_is_dispatched_to_localstack_sqs() -> None:
    settings = get_settings()

    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK

    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    command_id: str | None = None
    event_id: str | None = None

    queue = create_named_sqs_event_queue(
        settings,
        queue_name=settings.vehicle_command_queue_name,
    )

    await drain_queue(queue)

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

            vehicle_repository.add(vehicle)

            await uow.commit()

        service = IssueRemoteCommandService(session_factory)

        issued = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=f"outbox-sqs-{uuid4()}",
        )

        command_id = issued.command.id.value
        event_id = f"remote-command:{command_id}:requested"

        assert issued.created is True
        assert issued.command.status is RemoteCommandStatus.REQUESTED

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            before_result = await uow.session.execute(
                select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
            )

            before_dispatch = before_result.scalar_one()

            assert before_dispatch.published_at is None

        store = SQLAlchemyOutboxStore(session_factory)

        destinations = create_remote_command_outbox_destinations(settings)

        dispatcher = OutboxDispatcher(
            store=store,
            destinations=destinations,
            retry_policy=create_retry_policy(),
            batch_size=10,
            lease_seconds=30,
        )

        dispatch_result = await dispatcher.dispatch_batch()

        assert dispatch_result.claimed >= 1
        assert dispatch_result.published >= 1
        assert dispatch_result.retries_scheduled == 0
        assert dispatch_result.stale_claims == 0

        messages = await queue.receive_events(
            max_messages=10,
            wait_time_seconds=2,
        )

        received = next(
            (message for message in messages if message.event.event_id == event_id),
            None,
        )

        assert received is not None

        event = received.event

        assert event.event_type == REMOTE_COMMAND_REQUESTED_EVENT_TYPE
        assert event.payload["command_id"] == command_id
        assert event.payload["vehicle_id"] == vehicle.id.value
        assert event.payload["tenant_id"] == vehicle.tenant_id
        assert event.payload["command_type"] == RemoteCommandType.LOCK.value
        assert event.payload["status"] == RemoteCommandStatus.REQUESTED.value

        for message in messages:
            await queue.delete_message(message.receipt_handle)

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            after_result = await uow.session.execute(
                select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
            )

            after_dispatch = after_result.scalar_one()

            assert after_dispatch.published_at is not None
            assert after_dispatch.claim_token is None
            assert after_dispatch.lease_expires_at is None

    finally:
        await drain_queue(queue)

        async with engine.begin() as connection:
            if event_id is not None:
                await connection.execute(
                    delete(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
                )

            if command_id is not None:
                await connection.execute(
                    delete(RemoteCommandModel).where(RemoteCommandModel.id == command_id)
                )

            await connection.execute(
                delete(VehicleModel).where(VehicleModel.id == vehicle.id.value)
            )

        await engine.dispose()
