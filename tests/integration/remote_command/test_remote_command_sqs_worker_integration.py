from __future__ import annotations

from hashlib import sha256
from typing import NotRequired, Protocol, TypedDict, cast
from uuid import uuid4

import pytest
from sqlalchemy import delete

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.events import (
    create_remote_command_requested_event,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
)
from connected_vehicle.remote_command.worker_runtime import (
    create_remote_command_worker_runtime,
)
from connected_vehicle.vehicle import (
    VIN,
    Vehicle,
    VehicleId,
    VehicleStatus,
)
from connected_vehicle.vehicle.persistence.models import (
    VehicleModel,
)
from connected_vehicle.vehicle.persistence.repository import (
    SQLAlchemyVehicleRepository,
)
from enterprise_platform.cache.client import (
    create_cache_key_builder,
)
from enterprise_platform.cloud.client_factory import (
    AWSClientFactory,
)
from enterprise_platform.config.environment import (
    CloudRuntime,
)
from enterprise_platform.config.settings import (
    get_settings,
)
from enterprise_platform.database.engine import (
    create_database_engine,
)
from enterprise_platform.database.session import (
    create_session_factory,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from enterprise_platform.messaging.sqs_runtime import (
    create_named_sqs_event_queue,
)


class SQSCreateQueueResponse(TypedDict):
    QueueUrl: NotRequired[str]


class SQSAdminClient(Protocol):
    def create_queue(
        self,
        *,
        QueueName: str,
        Attributes: dict[str, str],
    ) -> SQSCreateQueueResponse: ...

    def delete_queue(
        self,
        *,
        QueueUrl: str,
    ) -> object: ...


class RecordingPublisher:
    def __init__(self) -> None:
        self.published: list[RemoteCommand] = []

    async def publish(
        self,
        command: RemoteCommand,
    ) -> None:
        self.published.append(command)


def create_active_vehicle() -> Vehicle:
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=VIN(uuid4().hex[:17].upper()),
        tenant_id="tenant-sqs-worker",
    )

    return vehicle.transition_to(VehicleStatus.ACTIVE)


async def persist_vehicle_and_command(
    session_factory: object,
    vehicle: Vehicle,
    command: RemoteCommand,
) -> None:
    async with SQLAlchemyUnitOfWork(
        session_factory  # type: ignore[arg-type]
    ) as uow:
        vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

        vehicle_repository.add(vehicle)

        await uow.commit()

    async with SQLAlchemyUnitOfWork(
        session_factory  # type: ignore[arg-type]
    ) as uow:
        command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

        command_repository.add(command)

        await uow.commit()


@pytest.mark.asyncio
async def test_remote_command_worker_processes_and_deduplicates_real_sqs_event() -> None:
    base_settings = get_settings()

    assert base_settings.cloud_runtime is CloudRuntime.LOCALSTACK

    queue_name = f"connected-vehicle-command-worker-{uuid4().hex}"

    redis_prefix = f"connected-vehicle:worker-integration:{uuid4().hex}"

    settings = base_settings.model_copy(
        update={
            "vehicle_command_queue_name": (queue_name),
            "redis_key_prefix": redis_prefix,
        }
    )

    engine = create_database_engine(settings)

    session_factory = create_session_factory(engine)

    sqs_client = cast(
        SQSAdminClient,
        AWSClientFactory(settings).sqs(),
    )

    queue_url: str | None = None
    runtime = None

    vehicle = create_active_vehicle()

    command = RemoteCommand.request(
        vehicle_id=vehicle.id,
        tenant_id=vehicle.tenant_id,
        command_type=RemoteCommandType.LOCK,
        idempotency_key=(f"worker-{uuid4()}"),
        ttl_seconds=300,
    )

    event = create_remote_command_requested_event(command)

    publisher = RecordingPublisher()

    key_builder = create_cache_key_builder(settings)

    redis_key = key_builder.build(
        "idempotency",
        sha256(event.event_id.encode("utf-8")).hexdigest(),
    )

    try:
        response = sqs_client.create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "1",
                "ReceiveMessageWaitTimeSeconds": "0",
            },
        )

        queue_url = response.get("QueueUrl")

        assert queue_url

        await persist_vehicle_and_command(
            session_factory,
            vehicle,
            command,
        )

        queue = create_named_sqs_event_queue(
            settings,
            queue_name=queue_name,
        )

        runtime = create_remote_command_worker_runtime(
            settings,
            session_factory,
            publisher,
        )

        await queue.send_event(event)

        first_result = await runtime.worker.run_once()

        assert first_result.received == 1
        assert first_result.processed == 1
        assert first_result.duplicates == 0
        assert first_result.in_progress == 0
        assert first_result.failed == 0

        assert len(publisher.published) == 1

        assert publisher.published[0].id == command.id

        assert publisher.published[0].status is RemoteCommandStatus.DISPATCHING

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            stored = await repository.get_by_id(command.id)

        assert stored is not None

        assert stored.status is RemoteCommandStatus.SENT

        assert await runtime.redis_resources.client.get(redis_key) == "completed"

        await queue.send_event(event)

        duplicate_result = await runtime.worker.run_once()

        assert duplicate_result.received == 1
        assert duplicate_result.processed == 0
        assert duplicate_result.duplicates == 1
        assert duplicate_result.in_progress == 0
        assert duplicate_result.failed == 0

        assert len(publisher.published) == 1

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            duplicate_stored = await repository.get_by_id(command.id)

        assert duplicate_stored is not None

        assert duplicate_stored.status is RemoteCommandStatus.SENT

    finally:
        if runtime is not None:
            await runtime.redis_resources.client.delete(redis_key)

            await runtime.close()

        async with engine.begin() as connection:
            await connection.execute(
                delete(RemoteCommandModel).where(RemoteCommandModel.id == command.id.value)
            )

            await connection.execute(
                delete(VehicleModel).where(VehicleModel.id == vehicle.id.value)
            )

        await engine.dispose()

        if queue_url is not None:
            sqs_client.delete_queue(QueueUrl=queue_url)
