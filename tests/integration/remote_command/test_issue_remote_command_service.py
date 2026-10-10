from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

import connected_vehicle.remote_command.service as remote_command_service_module
from connected_vehicle.remote_command import (
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
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
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.repositories.outbox import (
    SQLAlchemyOutboxRepository,
)
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork
from enterprise_platform.messaging.envelope import create_event_envelope
from enterprise_platform.reliability.outbox import PendingOutboxEvent


def create_active_vehicle() -> Vehicle:
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=VIN(uuid4().hex[:17].upper()),
        tenant_id="tenant-command-service",
    )

    return vehicle.transition_to(VehicleStatus.ACTIVE)


@pytest.mark.asyncio
async def test_issue_remote_command_commits_command_and_outbox_atomically() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    idempotency_key = f"issue-{uuid4()}"

    command_id: str | None = None
    event_id: str | None = None

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            repository.add(vehicle)

            await uow.commit()

        service = IssueRemoteCommandService(session_factory)

        result = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=idempotency_key,
        )

        command_id = result.command.id.value
        event_id = f"remote-command:{command_id}:requested"

        assert result.created is True
        assert result.command.status is RemoteCommandStatus.REQUESTED

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

            restored_command = await command_repository.get_by_id(result.command.id)

            outbox_result = await uow.session.execute(
                select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
            )

            outbox_event = outbox_result.scalar_one_or_none()

            assert outbox_event is not None

            outbox_event_type = outbox_event.event_type
            outbox_destination = outbox_event.destination

        assert restored_command == result.command
        assert outbox_event_type == REMOTE_COMMAND_REQUESTED_EVENT_TYPE
        assert outbox_destination == REMOTE_COMMAND_DESTINATION

    finally:
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


@pytest.mark.asyncio
async def test_issue_remote_command_rolls_back_when_outbox_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    idempotency_key = f"rollback-{uuid4()}"
    duplicate_event_id = f"duplicate-event-{uuid4()}"

    existing_event = create_event_envelope(
        event_id=duplicate_event_id,
        event_type=REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
        source="remote-command-rollback-test",
        payload={
            "seed": True,
        },
    )

    existing_pending = PendingOutboxEvent.from_event(
        existing_event,
        destination=REMOTE_COMMAND_DESTINATION,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)
            outbox_repository = SQLAlchemyOutboxRepository(uow.session)

            vehicle_repository.add(vehicle)
            outbox_repository.add(existing_pending)

            await uow.commit()

        duplicate_event = create_event_envelope(
            event_id=duplicate_event_id,
            event_type=REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
            source="remote-command-rollback-test",
            payload={
                "duplicate": True,
            },
        )

        monkeypatch.setattr(
            remote_command_service_module,
            "create_remote_command_requested_event",
            lambda _command: duplicate_event,
        )

        service = IssueRemoteCommandService(session_factory)

        with pytest.raises(IntegrityError):
            await service.issue(
                vehicle_id=vehicle.id,
                tenant_id=vehicle.tenant_id,
                command_type=RemoteCommandType.UNLOCK,
                idempotency_key=idempotency_key,
            )

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            command_result = await uow.session.execute(
                select(RemoteCommandModel.id).where(
                    RemoteCommandModel.vehicle_id == vehicle.id.value,
                    RemoteCommandModel.tenant_id == vehicle.tenant_id,
                    RemoteCommandModel.idempotency_key == idempotency_key,
                )
            )

            persisted_command_id = command_result.scalar_one_or_none()

            outbox_result = await uow.session.execute(
                select(OutboxEventModel.event_id).where(
                    OutboxEventModel.event_id == duplicate_event_id
                )
            )

            persisted_event_id = outbox_result.scalar_one_or_none()

        assert persisted_command_id is None
        assert persisted_event_id == duplicate_event_id

    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(RemoteCommandModel).where(RemoteCommandModel.vehicle_id == vehicle.id.value)
            )

            await connection.execute(
                delete(OutboxEventModel).where(OutboxEventModel.event_id == duplicate_event_id)
            )

            await connection.execute(
                delete(VehicleModel).where(VehicleModel.id == vehicle.id.value)
            )

        await engine.dispose()


@pytest.mark.asyncio
async def test_issue_remote_command_replays_idempotently() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    idempotency_key = f"idempotent-{uuid4()}"

    command_id: str | None = None
    event_id: str | None = None

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

            vehicle_repository.add(vehicle)

            await uow.commit()

        service = IssueRemoteCommandService(session_factory)

        first = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=idempotency_key,
        )

        second = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=idempotency_key,
        )

        command_id = first.command.id.value
        event_id = f"remote-command:{command_id}:requested"

        assert first.created is True
        assert second.created is False
        assert second.command == first.command
        assert second.command.id == first.command.id

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            command_count = await uow.session.scalar(
                select(func.count())
                .select_from(RemoteCommandModel)
                .where(
                    RemoteCommandModel.vehicle_id == vehicle.id.value,
                    RemoteCommandModel.tenant_id == vehicle.tenant_id,
                    RemoteCommandModel.idempotency_key == idempotency_key,
                )
            )

            outbox_count = await uow.session.scalar(
                select(func.count())
                .select_from(OutboxEventModel)
                .where(OutboxEventModel.event_id == event_id)
            )

        assert command_count == 1
        assert outbox_count == 1

    finally:
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


@pytest.mark.asyncio
async def test_issue_remote_command_rejects_idempotency_key_with_different_command_type() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    idempotency_key = f"conflict-type-{uuid4()}"

    command_id: str | None = None
    event_id: str | None = None

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

            vehicle_repository.add(vehicle)

            await uow.commit()

        service = IssueRemoteCommandService(session_factory)

        first = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=idempotency_key,
        )

        command_id = first.command.id.value
        event_id = f"remote-command:{command_id}:requested"

        with pytest.raises(
            match="different remote-command request",
        ):
            await service.issue(
                vehicle_id=vehicle.id,
                tenant_id=vehicle.tenant_id,
                command_type=RemoteCommandType.UNLOCK,
                idempotency_key=idempotency_key,
            )

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            command_count = await uow.session.scalar(
                select(func.count())
                .select_from(RemoteCommandModel)
                .where(
                    RemoteCommandModel.vehicle_id == vehicle.id.value,
                    RemoteCommandModel.tenant_id == vehicle.tenant_id,
                    RemoteCommandModel.idempotency_key == idempotency_key,
                )
            )

            outbox_count = await uow.session.scalar(
                select(func.count())
                .select_from(OutboxEventModel)
                .where(OutboxEventModel.event_id == event_id)
            )

        assert command_count == 1
        assert outbox_count == 1

    finally:
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


@pytest.mark.asyncio
async def test_issue_remote_command_rejects_idempotency_key_with_different_ttl() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    idempotency_key = f"conflict-ttl-{uuid4()}"

    command_id: str | None = None
    event_id: str | None = None

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

            vehicle_repository.add(vehicle)

            await uow.commit()

        service = IssueRemoteCommandService(session_factory)

        first = await service.issue(
            vehicle_id=vehicle.id,
            tenant_id=vehicle.tenant_id,
            command_type=RemoteCommandType.LOCK,
            idempotency_key=idempotency_key,
            ttl_seconds=60,
        )

        command_id = first.command.id.value
        event_id = f"remote-command:{command_id}:requested"

        with pytest.raises(
            match="different remote-command request",
        ):
            await service.issue(
                vehicle_id=vehicle.id,
                tenant_id=vehicle.tenant_id,
                command_type=RemoteCommandType.LOCK,
                idempotency_key=idempotency_key,
                ttl_seconds=120,
            )

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            command_count = await uow.session.scalar(
                select(func.count())
                .select_from(RemoteCommandModel)
                .where(
                    RemoteCommandModel.vehicle_id == vehicle.id.value,
                    RemoteCommandModel.tenant_id == vehicle.tenant_id,
                    RemoteCommandModel.idempotency_key == idempotency_key,
                )
            )

            outbox_count = await uow.session.scalar(
                select(func.count())
                .select_from(OutboxEventModel)
                .where(OutboxEventModel.event_id == event_id)
            )

        assert command_count == 1
        assert outbox_count == 1

    finally:
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
