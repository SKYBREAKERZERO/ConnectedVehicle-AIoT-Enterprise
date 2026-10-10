from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from apps.api.dependencies import get_session_factory
from connected_vehicle.device_data import CommandReport, TelemetrySample
from connected_vehicle.device_service import DeviceDataService
from enterprise_platform.security.authorization import require_permission, require_security_context
from enterprise_platform.security.context import SecurityContext
from enterprise_platform.security.exceptions import AuthorizationDeniedError
from enterprise_platform.security.identity import PrincipalType
from enterprise_platform.security.permissions import Permission

router = APIRouter(tags=["Device Data"])
Sessions = Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)]


def identity() -> SecurityContext:
    return require_security_context()


Identity = Annotated[SecurityContext, Depends(identity)]


def device(context: SecurityContext, vehicle: UUID, permission: Permission) -> str:
    require_permission(context, permission)
    principal = context.principal
    if (
        principal.principal_type is not PrincipalType.DEVICE
        or principal.device_vehicle_id != str(vehicle)
        or not principal.tenant_id
    ):
        raise AuthorizationDeniedError(permission)
    return principal.tenant_id


def tenant(context: SecurityContext, permission: Permission) -> str:
    require_permission(context, permission)
    if not context.principal.tenant_id:
        raise AuthorizationDeniedError(permission)
    return context.principal.tenant_id


@router.post(
    "/vehicles/{vehicle_id}/commands/{command_id}/reports", operation_id="reportCommandResult"
)
async def report_command(
    vehicle_id: UUID, command_id: UUID, report: CommandReport, context: Identity, sessions: Sessions
) -> dict[str, str]:
    status = await DeviceDataService(sessions).report(
        tenant=device(context, vehicle_id, Permission.COMMAND_REPORT),
        vehicle=str(vehicle_id),
        command_id=str(command_id),
        report=report,
    )
    return {"command_id": str(command_id), "status": status}


@router.get("/vehicles/{vehicle_id}/commands/{command_id}", operation_id="getCommandStatus")
async def command_status(
    vehicle_id: UUID, command_id: UUID, context: Identity, sessions: Sessions
) -> dict[str, str]:
    status = await DeviceDataService(sessions).command_status(
        tenant=tenant(context, Permission.VEHICLE_READ),
        vehicle=str(vehicle_id),
        command_id=str(command_id),
    )
    return {"command_id": str(command_id), "status": status}


@router.post("/vehicles/{vehicle_id}/telemetry", operation_id="ingestTelemetry", status_code=202)
async def ingest_telemetry(
    vehicle_id: UUID, sample: TelemetrySample, context: Identity, sessions: Sessions
) -> dict[str, bool]:
    created = await DeviceDataService(sessions).ingest(
        tenant=device(context, vehicle_id, Permission.TELEMETRY_PUBLISH),
        vehicle=str(vehicle_id),
        sample=sample,
    )
    return {"created": created}


@router.get("/vehicles/{vehicle_id}/telemetry", operation_id="queryTelemetry")
async def query_telemetry(
    vehicle_id: UUID,
    context: Identity,
    sessions: Sessions,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    before: AwareDatetime | None = None,
    before_event_id: UUID | None = None,
) -> list[dict[str, object]]:
    return await DeviceDataService(sessions).query(
        tenant=tenant(context, Permission.TELEMETRY_READ),
        vehicle=str(vehicle_id),
        limit=limit,
        before=before if isinstance(before, datetime) else None,
        before_event_id=str(before_event_id) if before_event_id else None,
    )
