from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.remote_command.application_errors import (
    RemoteCommandIdempotencyConflictError,
    RemoteCommandVehicleNotFoundError,
    RemoteCommandVehicleUnavailableError,
)
from connected_vehicle.remote_command.domain import (
    DEFAULT_REMOTE_COMMAND_TTL_SECONDS,
    RemoteCommand,
    RemoteCommandType,
)
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
    create_remote_command_requested_event,
)
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
)
from connected_vehicle.vehicle import VehicleId
from connected_vehicle.vehicle.persistence.repository import (
    SQLAlchemyVehicleRepository,
)
from enterprise_platform.database.repositories.outbox import (
    SQLAlchemyOutboxRepository,
)
from enterprise_platform.database.unit_of_work import (
    SQLAlchemyUnitOfWork,
)
from enterprise_platform.reliability.outbox import (
    PendingOutboxEvent,
)


@dataclass(frozen=True, slots=True)
class IssueRemoteCommandResult:
    command: RemoteCommand
    created: bool


class IssueRemoteCommandService:
    """Issue a remote command using one transactional write boundary."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._session_factory = session_factory

    async def issue(
        self,
        *,
        vehicle_id: VehicleId,
        tenant_id: str,
        command_type: RemoteCommandType,
        idempotency_key: str,
        ttl_seconds: int = DEFAULT_REMOTE_COMMAND_TTL_SECONDS,
    ) -> IssueRemoteCommandResult:
        normalized_tenant_id = tenant_id.strip()

        if not normalized_tenant_id:
            raise ValueError("Tenant ID must not be empty.")

        try:
            return await self._issue_once(
                vehicle_id=vehicle_id,
                tenant_id=normalized_tenant_id,
                command_type=command_type,
                idempotency_key=idempotency_key,
                ttl_seconds=ttl_seconds,
            )
        except IntegrityError:
            existing = await self._find_existing_after_conflict(
                vehicle_id=vehicle_id,
                tenant_id=normalized_tenant_id,
                idempotency_key=idempotency_key,
            )

            if existing is not None:
                self._ensure_idempotent_replay_matches(
                    existing=existing,
                    command_type=command_type,
                    ttl_seconds=ttl_seconds,
                )

                return IssueRemoteCommandResult(
                    command=existing,
                    created=False,
                )

            raise

    async def _issue_once(
        self,
        *,
        vehicle_id: VehicleId,
        tenant_id: str,
        command_type: RemoteCommandType,
        idempotency_key: str,
        ttl_seconds: int,
    ) -> IssueRemoteCommandResult:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            vehicle_repository = SQLAlchemyVehicleRepository(uow.session)
            command_repository = SQLAlchemyRemoteCommandRepository(uow.session)
            outbox_repository = SQLAlchemyOutboxRepository(uow.session)

            vehicle = await vehicle_repository.get_by_id_for_tenant(
                vehicle_id,
                tenant_id,
            )

            if vehicle is None:
                raise RemoteCommandVehicleNotFoundError(
                    "Vehicle was not found in the tenant scope."
                )

            existing = await command_repository.get_by_idempotency_key(
                tenant_id=tenant_id,
                vehicle_id=vehicle_id,
                idempotency_key=idempotency_key,
            )

            if existing is not None:
                self._ensure_idempotent_replay_matches(
                    existing=existing,
                    command_type=command_type,
                    ttl_seconds=ttl_seconds,
                )

                return IssueRemoteCommandResult(
                    command=existing,
                    created=False,
                )

            if not vehicle.accepts_remote_commands:
                raise RemoteCommandVehicleUnavailableError(
                    "Vehicle is not ACTIVE and cannot accept remote commands."
                )

            command = RemoteCommand.request(
                vehicle_id=vehicle.id,
                tenant_id=tenant_id,
                command_type=command_type,
                idempotency_key=idempotency_key,
                ttl_seconds=ttl_seconds,
            )

            event = create_remote_command_requested_event(command)

            pending = PendingOutboxEvent.from_event(
                event,
                destination=REMOTE_COMMAND_DESTINATION,
            )

            command_repository.add(command)
            outbox_repository.add(pending)

            await uow.commit()

            return IssueRemoteCommandResult(
                command=command,
                created=True,
            )

    async def _find_existing_after_conflict(
        self,
        *,
        vehicle_id: VehicleId,
        tenant_id: str,
        idempotency_key: str,
    ) -> RemoteCommand | None:
        async with SQLAlchemyUnitOfWork(self._session_factory) as uow:
            repository = SQLAlchemyRemoteCommandRepository(uow.session)

            return await repository.get_by_idempotency_key(
                tenant_id=tenant_id,
                vehicle_id=vehicle_id,
                idempotency_key=idempotency_key,
            )

    @staticmethod
    def _ensure_idempotent_replay_matches(
        *,
        existing: RemoteCommand,
        command_type: RemoteCommandType,
        ttl_seconds: int,
    ) -> None:
        existing_ttl_seconds = int((existing.expires_at - existing.created_at).total_seconds())

        if existing.command_type is not command_type or existing_ttl_seconds != ttl_seconds:
            raise RemoteCommandIdempotencyConflictError(
                "Idempotency key was already used for a different remote-command request."
            )
