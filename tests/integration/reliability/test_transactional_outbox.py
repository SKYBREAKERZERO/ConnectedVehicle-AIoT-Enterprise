from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import (
    Column,
    MetaData,
    String,
    Table,
    delete,
    insert,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import (
    create_database_engine,
)
from enterprise_platform.database.models.outbox import (
    OutboxEventModel,
)
from enterprise_platform.database.repositories.outbox import (
    SQLAlchemyOutboxRepository,
)
from enterprise_platform.database.session import (
    create_session_factory,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from enterprise_platform.messaging.envelope import (
    create_event_envelope,
)
from enterprise_platform.reliability.outbox import (
    PendingOutboxEvent,
)


def create_probe_table() -> tuple[MetaData, Table]:
    metadata = MetaData()

    table = Table(
        f"transaction_probe_{uuid4().hex}",
        metadata,
        Column(
            "id",
            String(36),
            primary_key=True,
        ),
        Column(
            "value",
            String(255),
            nullable=False,
        ),
    )

    return metadata, table


async def create_probe_schema(
    engine: AsyncEngine,
    metadata: MetaData,
) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)


async def read_transaction_state(
    engine: AsyncEngine,
    probe_table: Table,
    *,
    probe_id: str,
    event_id: str,
) -> tuple[bool, bool]:
    async with engine.connect() as connection:
        probe_value = await connection.scalar(
            select(probe_table.c.id).where(probe_table.c.id == probe_id)
        )

        outbox_value = await connection.scalar(
            select(OutboxEventModel.event_id).where(OutboxEventModel.event_id == event_id)
        )

    return (
        probe_value is not None,
        outbox_value is not None,
    )


async def cleanup(
    engine: AsyncEngine,
    metadata: MetaData,
    *,
    event_id: str,
) -> None:
    async with engine.begin() as connection:
        await connection.execute(
            delete(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
        )

        await connection.run_sync(metadata.drop_all)


@pytest.mark.asyncio
async def test_business_and_outbox_commit_atomically() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    metadata, probe_table = create_probe_table()

    probe_id = str(uuid4())
    event_id = f"event-{uuid4()}"

    event = create_event_envelope(
        event_id=event_id,
        event_type="vehicle.command.requested",
        source="transactional-outbox-integration",
        payload={
            "vehicle_id": "VIN-OUTBOX-001",
            "command": "unlock",
        },
    )

    pending = PendingOutboxEvent.from_event(
        event,
        destination="vehicle-command",
    )

    await create_probe_schema(
        engine,
        metadata,
    )

    try:
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            await uow.session.execute(
                insert(probe_table).values(
                    id=probe_id,
                    value="business-record",
                )
            )

            repository = SQLAlchemyOutboxRepository(uow.session)

            repository.add(pending)

            await uow.commit()

        probe_exists, outbox_exists = await read_transaction_state(
            engine,
            probe_table,
            probe_id=probe_id,
            event_id=event_id,
        )

        assert probe_exists is True
        assert outbox_exists is True

    finally:
        await cleanup(
            engine,
            metadata,
            event_id=event_id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_business_and_outbox_rollback_atomically() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    metadata, probe_table = create_probe_table()

    probe_id = str(uuid4())
    event_id = f"event-{uuid4()}"

    event = create_event_envelope(
        event_id=event_id,
        event_type="vehicle.command.requested",
        source="transactional-outbox-integration",
        payload={
            "vehicle_id": "VIN-OUTBOX-002",
            "command": "lock",
        },
    )

    pending = PendingOutboxEvent.from_event(
        event,
        destination="vehicle-command",
    )

    await create_probe_schema(
        engine,
        metadata,
    )

    try:
        with pytest.raises(
            RuntimeError,
            match="force transaction rollback",
        ):
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    insert(probe_table).values(
                        id=probe_id,
                        value="business-record",
                    )
                )

                repository = SQLAlchemyOutboxRepository(uow.session)

                repository.add(pending)

                # Force both INSERT operations to reach
                # PostgreSQL before the rollback.
                await uow.session.flush()

                raise RuntimeError("force transaction rollback")

        probe_exists, outbox_exists = await read_transaction_state(
            engine,
            probe_table,
            probe_id=probe_id,
            event_id=event_id,
        )

        assert probe_exists is False
        assert outbox_exists is False

    finally:
        await cleanup(
            engine,
            metadata,
            event_id=event_id,
        )

        await engine.dispose()


@pytest.mark.asyncio
async def test_outbox_constraint_failure_rolls_back_business_write() -> None:
    settings = get_settings()
    engine = create_database_engine(settings)
    session_factory = create_session_factory(engine)

    metadata, probe_table = create_probe_table()

    probe_id = str(uuid4())
    event_id = f"event-{uuid4()}"

    event = create_event_envelope(
        event_id=event_id,
        event_type="vehicle.command.requested",
        source="transactional-outbox-integration",
        payload={
            "vehicle_id": "VIN-OUTBOX-003",
            "command": "start",
        },
    )

    pending = PendingOutboxEvent.from_event(
        event,
        destination="vehicle-command",
    )

    await create_probe_schema(
        engine,
        metadata,
    )

    try:
        # Establish an existing outbox event so the
        # second transaction violates unique(event_id).
        async with SQLAlchemyUnitOfWork(session_factory) as uow:
            repository = SQLAlchemyOutboxRepository(uow.session)

            repository.add(pending)

            await uow.commit()

        with pytest.raises(IntegrityError):
            async with SQLAlchemyUnitOfWork(session_factory) as uow:
                await uow.session.execute(
                    insert(probe_table).values(
                        id=probe_id,
                        value="must-rollback",
                    )
                )

                repository = SQLAlchemyOutboxRepository(uow.session)

                repository.add(pending)

                await uow.commit()

        probe_exists, outbox_exists = await read_transaction_state(
            engine,
            probe_table,
            probe_id=probe_id,
            event_id=event_id,
        )

        assert probe_exists is False
        assert outbox_exists is True

    finally:
        await cleanup(
            engine,
            metadata,
            event_id=event_id,
        )

        await engine.dispose()
