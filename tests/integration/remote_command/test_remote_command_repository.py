from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from connected_vehicle.remote_command import (
    RemoteCommand,
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
)
from connected_vehicle.vehicle.persistence.models import VehicleModel
from connected_vehicle.vehicle.persistence.repository import (
    SQLAlchemyVehicleRepository,
)
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.database.unit_of_work import SQLAlchemyUnitOfWork


def create_test_vehicle() -> Vehicle:
    return Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=VIN(uuid4().hex[:17].upper()),
        tenant_id="tenant-command-integration",
    )


def create_test_command(
    vehicle: Vehicle,
) -> RemoteCommand:
    return RemoteCommand.request(
        vehicle_id=vehicle.id,
        tenant_id=vehicle.tenant_id,
        command_type=RemoteCommandType.LOCK,
        idempotency_key=f"request-{uuid4()}",
    )


async def cleanup_records(
    engine: AsyncEngine,
    *,
    command: RemoteCommand,
    vehicle: Vehicle,
) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            delete(RemoteCommandModel).where(RemoteCommandModel.id == command.id.value)
        )

        await connection.execute(delete(VehicleModel).where(VehicleModel.id == vehicle.id.value))


@pytest.mark.asyncio
async def test_remote_command_repository_persists_and_reads_command() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()
    command = create_test_command(vehicle)

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)
            command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

            vehicle_repository.add(vehicle)

            # The command row has a database FK to vehicles.id.
            # Flush the aggregate root first because these two ORM
            # models intentionally do not have an ORM relationship.
            await uow.session.flush()

            command_repository.add(command)

            await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            by_id = await repository.get_by_id(command.id)

            by_tenant = await repository.get_by_id_for_tenant(
                command.id,
                vehicle.tenant_id,
            )

            wrong_tenant = await repository.get_by_id_for_tenant(
                command.id,
                "tenant-other",
            )

            by_idempotency = await repository.get_by_idempotency_key(
                tenant_id=vehicle.tenant_id,
                vehicle_id=vehicle.id,
                idempotency_key=command.idempotency_key,
            )

        assert by_id == command
        assert by_tenant == command
        assert wrong_tenant is None
        assert by_idempotency == command

    finally:
        await cleanup_records(
            engine,
            command=command,
            vehicle=vehicle,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_remote_command_repository_saves_status_transition() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()
    command = create_test_command(vehicle)

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)
            command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

            vehicle_repository.add(vehicle)
            await uow.session.flush()

            command_repository.add(command)

            await uow.commit()

        queued_command = command.transition_to(
            RemoteCommandStatus.QUEUED,
            now=command.updated_at + timedelta(seconds=1),
        )

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            saved = await repository.save(queued_command)

            await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            restored = await repository.get_by_id(command.id)

        assert saved is True
        assert restored == queued_command
        assert restored.status is RemoteCommandStatus.QUEUED

    finally:
        await cleanup_records(
            engine,
            command=command,
            vehicle=vehicle,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_remote_command_repository_rejects_duplicate_idempotency_key() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()
    first_command = create_test_command(vehicle)

    duplicate_command = RemoteCommand.request(
        vehicle_id=vehicle.id,
        tenant_id=vehicle.tenant_id,
        command_type=RemoteCommandType.UNLOCK,
        idempotency_key=first_command.idempotency_key,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)

            vehicle_repository.add(vehicle)

            await uow.commit()

        with pytest.raises(IntegrityError):
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                repository = SQLAlchemyRemoteCommandRepository(uow.session)

                repository.add(first_command)
                repository.add(duplicate_command)

                await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            restored_first = await repository.get_by_id(first_command.id)
            restored_duplicate = await repository.get_by_id(duplicate_command.id)

        assert restored_first is None
        assert restored_duplicate is None

    finally:
        await cleanup_records(
            engine,
            command=first_command,
            vehicle=vehicle,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_remote_command_repository_rejects_unknown_vehicle() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    command = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-command-integration",
        command_type=RemoteCommandType.LOCK,
        idempotency_key=f"request-{uuid4()}",
    )

    try:
        with pytest.raises(IntegrityError):
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                repository = SQLAlchemyRemoteCommandRepository(uow.session)

                repository.add(command)

                await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            restored = await repository.get_by_id(command.id)

        assert restored is None

    finally:
        async with engine.begin() as connection:
            await connection.execute(
                delete(RemoteCommandModel).where(RemoteCommandModel.id == command.id.value)
            )

        await engine.dispose()


@pytest.mark.asyncio
async def test_remote_command_repository_get_for_update_serializes_access() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()
    command = create_test_command(vehicle)

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)
            command_repository = SQLAlchemyRemoteCommandRepository(uow.session)

            vehicle_repository.add(vehicle)
            await uow.session.flush()

            command_repository.add(command)

            await uow.commit()

        second_attempt_started = asyncio.Event()
        second_lock_acquired = asyncio.Event()

        async def acquire_second_lock() -> RemoteCommand | None:
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                repository = SQLAlchemyRemoteCommandRepository(uow.session)

                second_attempt_started.set()

                locked_command = await repository.get_for_update(command.id)

                second_lock_acquired.set()

                await uow.commit()

                return locked_command

        async with SQLAlchemyUnitOfWork(session_factory) as first_uow:
            first_repository = SQLAlchemyRemoteCommandRepository(first_uow.session)

            first_locked = await first_repository.get_for_update(command.id)

            assert first_locked == command

            second_task = asyncio.create_task(acquire_second_lock())

            await second_attempt_started.wait()

            try:
                await asyncio.wait_for(
                    asyncio.shield(second_task),
                    timeout=0.2,
                )
            except TimeoutError:
                pass
            else:
                pytest.fail(
                    "Second transaction acquired the row lock "
                    "before the first transaction released it."
                )

            assert second_lock_acquired.is_set() is False

            await first_uow.commit()

            second_locked = await asyncio.wait_for(
                second_task,
                timeout=2.0,
            )

        assert second_locked == command
        assert second_lock_acquired.is_set() is True

    finally:
        await cleanup_records(
            engine,
            command=command,
            vehicle=vehicle,
        )

        await engine.dispose()
