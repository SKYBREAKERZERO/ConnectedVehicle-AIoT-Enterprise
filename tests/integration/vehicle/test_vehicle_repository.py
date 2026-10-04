from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import delete

from connected_vehicle.vehicle import VIN, Vehicle, VehicleId
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
        tenant_id="tenant-integration-001",
    )


async def cleanup_vehicle(
    engine,
    *,
    vehicle_id: VehicleId,
) -> None:
    async with engine.begin() as connection:
        await connection.execute(delete(VehicleModel).where(VehicleModel.id == vehicle_id.value))


@pytest.mark.asyncio
async def test_vehicle_repository_persists_and_reads_vehicle() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            repository.add(vehicle)

            await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            by_id = await repository.get_by_id(vehicle.id)
            by_vin = await repository.get_by_vin(vehicle.vin)
            by_tenant = await repository.get_by_id_for_tenant(
                vehicle.id,
                vehicle.tenant_id,
            )
            wrong_tenant = await repository.get_by_id_for_tenant(
                vehicle.id,
                "tenant-other",
            )

        assert by_id == vehicle
        assert by_vin == vehicle
        assert by_tenant == vehicle
        assert wrong_tenant is None

    finally:
        await cleanup_vehicle(
            engine,
            vehicle_id=vehicle.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_vehicle_repository_saves_status_transition() -> None:
    from connected_vehicle.vehicle import VehicleStatus

    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    vehicle = create_test_vehicle()

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            repository.add(vehicle)

            await uow.commit()

        active = vehicle.transition_to(
            VehicleStatus.ACTIVE,
        )

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            saved = await repository.save(active)

            assert saved is True

            await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            restored = await repository.get_by_id(vehicle.id)

        assert restored is not None
        assert restored.status is VehicleStatus.ACTIVE
        assert restored.accepts_remote_commands is True
        assert restored.updated_at == active.updated_at

    finally:
        await cleanup_vehicle(
            engine,
            vehicle_id=vehicle.id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_duplicate_vin_rolls_back_entire_transaction() -> None:
    from sqlalchemy.exc import IntegrityError

    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    duplicate_vin = VIN(uuid4().hex[:17].upper())

    first = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=duplicate_vin,
        tenant_id="tenant-integration-001",
    )

    second = Vehicle.create(
        vehicle_id=VehicleId.new(),
        vin=duplicate_vin,
        tenant_id="tenant-integration-001",
    )

    try:
        with pytest.raises(IntegrityError):
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                repository = SQLAlchemyVehicleRepository(uow.session)

                repository.add(first)
                repository.add(second)

                await uow.commit()

        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyVehicleRepository(uow.session)

            restored_first = await repository.get_by_id(first.id)
            restored_second = await repository.get_by_id(second.id)
            restored_by_vin = await repository.get_by_vin(duplicate_vin)

        assert restored_first is None
        assert restored_second is None
        assert restored_by_vin is None

    finally:
        await cleanup_vehicle(
            engine,
            vehicle_id=first.id,
        )
        await cleanup_vehicle(
            engine,
            vehicle_id=second.id,
        )

        await engine.dispose()
