from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandId,
)
from connected_vehicle.remote_command.persistence.mapper import (
    apply_remote_command_to_model,
    remote_command_from_model,
    remote_command_to_model,
)
from connected_vehicle.remote_command.persistence.models import (
    RemoteCommandModel,
)
from connected_vehicle.vehicle import VehicleId


class SQLAlchemyRemoteCommandRepository:
    """SQLAlchemy persistence adapter for RemoteCommand."""

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self._session = session

    def add(
        self,
        command: RemoteCommand,
    ) -> None:
        model = remote_command_to_model(command)
        self._session.add(model)

    async def get_by_id(
        self,
        command_id: RemoteCommandId,
    ) -> RemoteCommand | None:
        statement = select(RemoteCommandModel).where(RemoteCommandModel.id == command_id.value)

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return remote_command_from_model(model)

    async def get_by_id_for_tenant(
        self,
        command_id: RemoteCommandId,
        tenant_id: str,
    ) -> RemoteCommand | None:
        normalized_tenant_id = tenant_id.strip()

        if not normalized_tenant_id:
            raise ValueError("Tenant ID must not be empty.")

        statement = select(RemoteCommandModel).where(
            RemoteCommandModel.id == command_id.value,
            RemoteCommandModel.tenant_id == normalized_tenant_id,
        )

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return remote_command_from_model(model)

    async def get_by_idempotency_key(
        self,
        *,
        tenant_id: str,
        vehicle_id: VehicleId,
        idempotency_key: str,
    ) -> RemoteCommand | None:
        normalized_tenant_id = tenant_id.strip()
        normalized_idempotency_key = idempotency_key.strip()

        if not normalized_tenant_id:
            raise ValueError("Tenant ID must not be empty.")

        if not normalized_idempotency_key:
            raise ValueError("Idempotency key must not be empty.")

        statement = select(RemoteCommandModel).where(
            RemoteCommandModel.tenant_id == normalized_tenant_id,
            RemoteCommandModel.vehicle_id == vehicle_id.value,
            RemoteCommandModel.idempotency_key == normalized_idempotency_key,
        )

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return remote_command_from_model(model)

    async def get_for_update(
        self,
        command_id: RemoteCommandId,
    ) -> RemoteCommand | None:
        statement = (
            select(RemoteCommandModel)
            .where(RemoteCommandModel.id == command_id.value)
            .with_for_update()
        )

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return None

        return remote_command_from_model(model)

    async def save(
        self,
        command: RemoteCommand,
    ) -> bool:
        statement = select(RemoteCommandModel).where(RemoteCommandModel.id == command.id.value)

        result = await self._session.execute(statement)
        model = result.scalar_one_or_none()

        if model is None:
            return False

        apply_remote_command_to_model(
            model,
            command,
        )

        return True
