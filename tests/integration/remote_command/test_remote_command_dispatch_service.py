from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from connected_vehicle.remote_command.dispatch_service import (
    RemoteCommandDispatchCommandNotFoundError,
    RemoteCommandDispatchOutcome,
    RemoteCommandDispatchService,
)
from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
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
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import (
    create_database_engine,
)
from enterprise_platform.database.session import (
    create_session_factory,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)

BASE_TIME = datetime(
    2030,
    1,
    1,
    12,
    0,
    tzinfo=UTC,
)


def create_active_vehicle() -> Vehicle:
    vehicle = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=VIN(uuid4().hex[:17].upper()),
        tenant_id="tenant-dispatch-service",
    )

    return vehicle.transition_to(VehicleStatus.ACTIVE)


def create_requested_command(
    vehicle: Vehicle,
    *,
    ttl_seconds: int = 300,
) -> RemoteCommand:
    return RemoteCommand.request(
        vehicle_id=vehicle.id,
        tenant_id=vehicle.tenant_id,
        command_type=RemoteCommandType.LOCK,
        idempotency_key=f"dispatch-{uuid4()}",
        ttl_seconds=ttl_seconds,
        now=BASE_TIME,
    )


async def persist_vehicle_and_command(
    session_factory: async_sessionmaker[AsyncSession],
    vehicle: Vehicle,
    command: RemoteCommand,
) -> None:
    async with SQLAlchemyUnitOfWork(session_factory) as uow:
        vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

        vehicle_repository.add(vehicle)

        await uow.commit()

    async with SQLAlchemyUnitOfWork(session_factory) as uow:
        command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

        command_repository.add(command)

        await uow.commit()


async def read_command(
    session_factory: async_sessionmaker[AsyncSession],
    command_id: RemoteCommandId,
) -> RemoteCommand:
    async with SQLAlchemyUnitOfWork(session_factory) as uow:
        repository = SQLAlchemyRemoteCommandRepository(uow.session)

        command = await repository.get_by_id(command_id)

    assert command is not None

    return command


async def cleanup(
    engine: AsyncEngine,
    *,
    vehicle_id: VehicleId,
    command_id: RemoteCommandId,
) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            delete(RemoteCommandModel).where(RemoteCommandModel.id == command_id.value)
        )

        await connection.execute(delete(VehicleModel).where(VehicleModel.id == vehicle_id.value))


class RecordingPublisher:
    def __init__(
        self,
        *,
        fail: bool = False,
    ) -> None:
        self.fail = fail
        self.published: list[RemoteCommand] = []

    async def publish(
        self,
        command: RemoteCommand,
    ) -> None:
        self.published.append(command)

        if self.fail:
            raise RuntimeError("simulated transport failure")


class LockProbePublisher:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._session_factory = session_factory
        self.published: list[RemoteCommand] = []

    async def publish(
        self,
        command: RemoteCommand,
    ) -> None:
        async def acquire_same_row_lock() -> None:
            async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
                repository = SQLAlchemyRemoteCommandRepository(uow.session)

                locked = await repository.get_for_update(command.id)

                assert locked is not None
                assert locked.status is RemoteCommandStatus.DISPATCHING

        # This would time out if dispatch() still held the
        # PostgreSQL FOR UPDATE lock while invoking publish().
        await asyncio.wait_for(
            acquire_same_row_lock(),
            timeout=2.0,
        )

        self.published.append(command)


@pytest.mark.asyncio
async def test_dispatch_progresses_requested_to_sent_without_holding_db_lock() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    command = create_requested_command(vehicle)

    try:
        await persist_vehicle_and_command(
            session_factory,
            vehicle,
            command,
        )

        publisher = LockProbePublisher(session_factory)

        service = RemoteCommandDispatchService(
            session_factory,
            publisher,
        )

        result = await service.dispatch(
            command.id,
            now=BASE_TIME + timedelta(seconds=1),
        )

        assert result.outcome is RemoteCommandDispatchOutcome.PUBLISHED
        assert result.command.status is RemoteCommandStatus.SENT

        assert len(publisher.published) == 1
        assert publisher.published[0].status is RemoteCommandStatus.DISPATCHING

        restored = await read_command(
            session_factory,
            command.id,
        )

        assert restored.status is RemoteCommandStatus.SENT

    finally:
        await cleanup(
            engine,
            vehicle_id=vehicle.id,
            command_id=command.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_publish_failure_leaves_dispatching_and_redelivery_republishes() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    command = create_requested_command(vehicle)

    try:
        await persist_vehicle_and_command(
            session_factory,
            vehicle,
            command,
        )

        failing_publisher = RecordingPublisher(fail=True)

        failing_service = RemoteCommandDispatchService(
            session_factory,
            failing_publisher,
        )

        with pytest.raises(
            RuntimeError,
            match="simulated transport failure",
        ):
            await failing_service.dispatch(
                command.id,
                now=BASE_TIME + timedelta(seconds=1),
            )

        after_failure = await read_command(
            session_factory,
            command.id,
        )

        assert after_failure.status is RemoteCommandStatus.DISPATCHING
        assert len(failing_publisher.published) == 1

        recovery_publisher = RecordingPublisher()

        recovery_service = RemoteCommandDispatchService(
            session_factory,
            recovery_publisher,
        )

        result = await recovery_service.dispatch(
            command.id,
            now=BASE_TIME + timedelta(seconds=2),
        )

        assert result.outcome is RemoteCommandDispatchOutcome.PUBLISHED
        assert result.command.status is RemoteCommandStatus.SENT
        assert len(recovery_publisher.published) == 1
        assert recovery_publisher.published[0].status is RemoteCommandStatus.DISPATCHING

    finally:
        await cleanup(
            engine,
            vehicle_id=vehicle.id,
            command_id=command.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_sent_command_is_not_published_again() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    command = create_requested_command(vehicle)

    try:
        await persist_vehicle_and_command(
            session_factory,
            vehicle,
            command,
        )

        first_publisher = RecordingPublisher()

        first_service = RemoteCommandDispatchService(
            session_factory,
            first_publisher,
        )

        first = await first_service.dispatch(
            command.id,
            now=BASE_TIME + timedelta(seconds=1),
        )

        assert first.outcome is RemoteCommandDispatchOutcome.PUBLISHED

        duplicate_publisher = RecordingPublisher()

        duplicate_service = RemoteCommandDispatchService(
            session_factory,
            duplicate_publisher,
        )

        duplicate = await duplicate_service.dispatch(
            command.id,
            now=BASE_TIME + timedelta(seconds=2),
        )

        assert duplicate.outcome is RemoteCommandDispatchOutcome.ALREADY_HANDLED
        assert duplicate.command.status is RemoteCommandStatus.SENT
        assert duplicate_publisher.published == []

    finally:
        await cleanup(
            engine,
            vehicle_id=vehicle.id,
            command_id=command.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_command_is_marked_expired_without_publish() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_active_vehicle()
    command = create_requested_command(
        vehicle,
        ttl_seconds=1,
    )

    try:
        await persist_vehicle_and_command(
            session_factory,
            vehicle,
            command,
        )

        publisher = RecordingPublisher()

        service = RemoteCommandDispatchService(
            session_factory,
            publisher,
        )

        result = await service.dispatch(
            command.id,
            now=BASE_TIME + timedelta(seconds=2),
        )

        assert result.outcome is RemoteCommandDispatchOutcome.EXPIRED
        assert result.command.status is RemoteCommandStatus.EXPIRED
        assert publisher.published == []

        restored = await read_command(
            session_factory,
            command.id,
        )

        assert restored.status is RemoteCommandStatus.EXPIRED

    finally:
        await cleanup(
            engine,
            vehicle_id=vehicle.id,
            command_id=command.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_missing_command_is_not_silently_acknowledged() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    publisher = RecordingPublisher()

    service = RemoteCommandDispatchService(
        session_factory,
        publisher,
    )

    try:
        with pytest.raises(
            RemoteCommandDispatchCommandNotFoundError,
            match="was not found",
        ):
            await service.dispatch(
                RemoteCommandId.new(),
                now=BASE_TIME,
            )

        assert publisher.published == []

    finally:
        await engine.dispose()
