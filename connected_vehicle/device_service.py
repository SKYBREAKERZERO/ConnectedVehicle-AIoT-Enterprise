from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, text, tuple_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle.device_data import (
    CommandReport,
    CommandReportModel,
    TelemetrySample,
    TelemetrySampleModel,
)
from connected_vehicle.remote_command.domain import RemoteCommandId, RemoteCommandStatus
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
)
from connected_vehicle.vehicle.persistence.models import VehicleModel
from enterprise_platform.errors.base import ConflictError, ResourceNotFoundError


class DeviceDataService:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def report(
        self, *, tenant: str, vehicle: str, command_id: str, report: CommandReport
    ) -> str:
        async with self.sessions() as session, session.begin():
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": str(report.event_id)},
            )
            repository = SQLAlchemyRemoteCommandRepository(session)
            command = await repository.get_for_update(RemoteCommandId(command_id))
            if command is None or command.tenant_id != tenant or str(command.vehicle_id) != vehicle:
                raise ResourceNotFoundError()
            previous = await session.get(CommandReportModel, str(report.event_id))
            body = report.model_dump(mode="json")
            if previous:
                if previous.command_id != command_id or previous.report != body:
                    raise ConflictError("Event ID already belongs to a different report.")
                return command.status.value
            if report.occurred_at < command.created_at:
                raise ConflictError("Report predates the command.")
            target = RemoteCommandStatus(report.status)
            if command.status == target:
                pass
            elif command.is_terminal and target is RemoteCommandStatus.ACKNOWLEDGED:
                pass  # Delayed ACK records receipt without regressing execution results.
            elif command.is_terminal:
                raise ConflictError("Command is already terminal.")
            elif command.status not in {
                RemoteCommandStatus.DISPATCHING,
                RemoteCommandStatus.SENT,
                RemoteCommandStatus.ACKNOWLEDGED,
            }:
                raise ConflictError("Command was not dispatched.")
            else:
                now = max(datetime.now(UTC), command.updated_at)
                if command.status is RemoteCommandStatus.DISPATCHING:
                    command = command.transition_to(RemoteCommandStatus.SENT, now=now)
                if command.status is RemoteCommandStatus.SENT:
                    command = command.transition_to(RemoteCommandStatus.ACKNOWLEDGED, now=now)
                if command.status != target:
                    command = command.transition_to(target, now=now)
                await repository.save(command)
            session.add(
                CommandReportModel(
                    event_id=str(report.event_id),
                    command_id=command_id,
                    tenant_id=tenant,
                    vehicle_id=vehicle,
                    report=body,
                    received_at=datetime.now(UTC),
                )
            )
            return command.status.value

    async def ingest(self, *, tenant: str, vehicle: str, sample: TelemetrySample) -> bool:
        async with self.sessions() as session, session.begin():
            # Serialize device ingestion on a transaction-scoped advisory lock:
            # no UPDATE privilege on vehicles and no duplicate insert race.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": str(sample.event_id)},
            )
            exists = await session.scalar(
                select(VehicleModel.id).where(
                    VehicleModel.id == vehicle, VehicleModel.tenant_id == tenant
                )
            )
            if not exists:
                raise ResourceNotFoundError()
            previous = await session.get(TelemetrySampleModel, str(sample.event_id))
            body = sample.model_dump(mode="json")
            if previous:
                if (
                    previous.tenant_id != tenant
                    or previous.vehicle_id != vehicle
                    or previous.sample != body
                ):
                    raise ConflictError("Event ID already belongs to a different sample.")
                return False
            session.add(
                TelemetrySampleModel(
                    event_id=str(sample.event_id),
                    tenant_id=tenant,
                    vehicle_id=vehicle,
                    measured_at=sample.measured_at,
                    received_at=datetime.now(UTC),
                    sample=body,
                )
            )
            return True

    async def query(
        self,
        *,
        tenant: str,
        vehicle: str,
        limit: int,
        before: datetime | None = None,
        before_event_id: str | None = None,
    ) -> list[dict[str, object]]:
        async with self.sessions() as session:
            statement = select(TelemetrySampleModel).where(
                TelemetrySampleModel.tenant_id == tenant, TelemetrySampleModel.vehicle_id == vehicle
            )
            if before is not None:
                if before_event_id is None:
                    statement = statement.where(TelemetrySampleModel.measured_at < before)
                else:
                    statement = statement.where(
                        tuple_(TelemetrySampleModel.measured_at, TelemetrySampleModel.event_id)
                        < tuple_(before, before_event_id)
                    )
            rows = (
                await session.execute(
                    statement.order_by(
                        TelemetrySampleModel.measured_at.desc(),
                        TelemetrySampleModel.event_id.desc(),
                    ).limit(limit)
                )
            ).scalars()
            return [row.sample for row in rows]

    async def command_status(self, *, tenant: str, vehicle: str, command_id: str) -> str:
        async with self.sessions() as session:
            command = await SQLAlchemyRemoteCommandRepository(session).get_by_id_for_tenant(
                RemoteCommandId(command_id), tenant
            )
            if command is None or str(command.vehicle_id) != vehicle:
                raise ResourceNotFoundError()
            return command.status.value
