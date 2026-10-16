from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query

from apps.api.routers.device_data import Identity, Sessions, tenant
from connected_vehicle.ota.contracts import (
    CancelJob,
    ECURegistration,
    ECUResult,
    ECUView,
    FirmwareRegistration,
    FirmwareResult,
    FirmwareView,
    JobRequest,
    JobResult,
    JobView,
)
from connected_vehicle.ota.service import OTAService
from enterprise_platform.security.permissions import Permission

router = APIRouter(tags=["OTA Foundation"])
Key = Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=255)]
Limit = Annotated[int, Query(ge=1, le=100)]


def service(sessions: Sessions) -> OTAService:
    return OTAService(sessions)


Service = Annotated[OTAService, Depends(service)]


@router.put("/vehicles/{vehicle_id}/ecus/{ecu_id}", operation_id="registerECU")
async def register_ecu(
    vehicle_id: UUID,
    ecu_id: UUID,
    body: ECURegistration,
    context: Identity,
    ota: Service,
) -> ECUResult:
    return await ota.register_ecu(
        tenant(context, Permission.OTA_MANAGE),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
        body,
    )


@router.get("/vehicles/{vehicle_id}/ecus", operation_id="listECUs")
async def list_ecus(
    vehicle_id: UUID,
    context: Identity,
    ota: Service,
    limit: Limit = 50,
    after: UUID | None = None,
) -> list[ECUView]:
    return await ota.list_ecus(
        tenant(context, Permission.OTA_READ), str(vehicle_id), limit, str(after) if after else ""
    )


@router.get("/vehicles/{vehicle_id}/ecus/{ecu_id}", operation_id="getECU")
async def get_ecu(vehicle_id: UUID, ecu_id: UUID, context: Identity, ota: Service) -> ECUView:
    return await ota.get_ecu(tenant(context, Permission.OTA_READ), str(vehicle_id), str(ecu_id))


@router.post("/ota/firmware-releases", operation_id="registerFirmwareRelease", status_code=201)
async def register_release(
    body: FirmwareRegistration,
    key: Key,
    context: Identity,
    ota: Service,
) -> FirmwareResult:
    return await ota.register_firmware(
        tenant(context, Permission.OTA_MANAGE), context.principal.principal_id, key, body
    )


@router.get("/ota/firmware-releases", operation_id="listFirmwareReleases")
async def list_releases(
    context: Identity,
    ota: Service,
    limit: Limit = 50,
    after: UUID | None = None,
) -> list[FirmwareView]:
    return await ota.list_firmware(
        tenant(context, Permission.OTA_READ), limit, str(after) if after else ""
    )


@router.get("/ota/firmware-releases/{release_id}", operation_id="getFirmwareRelease")
async def get_release(release_id: UUID, context: Identity, ota: Service) -> FirmwareView:
    return await ota.get_firmware(tenant(context, Permission.OTA_READ), str(release_id))


@router.post(
    "/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs",
    operation_id="createOTAJob",
    status_code=202,
    description="Persist intent awaiting artifact verification; no device execution.",
)
async def create_job(
    vehicle_id: UUID,
    ecu_id: UUID,
    body: JobRequest,
    key: Key,
    context: Identity,
    ota: Service,
) -> JobResult:
    return await ota.create_job(
        tenant(context, Permission.OTA_MANAGE),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
        str(body.release_id),
        key,
    )


@router.get("/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs", operation_id="listOTAJobs")
async def list_jobs(
    vehicle_id: UUID,
    ecu_id: UUID,
    context: Identity,
    ota: Service,
    limit: Limit = 50,
    after: UUID | None = None,
) -> list[JobView]:
    return await ota.list_jobs(
        tenant(context, Permission.OTA_READ),
        str(vehicle_id),
        str(ecu_id),
        limit,
        str(after) if after else "",
    )


@router.get("/ota/jobs/{job_id}", operation_id="getOTAJob")
async def get_job(job_id: UUID, context: Identity, ota: Service) -> JobView:
    return await ota.get_job(tenant(context, Permission.OTA_READ), str(job_id))


@router.post("/ota/jobs/{job_id}/cancel", operation_id="cancelOTAJob")
async def cancel_job(
    job_id: UUID,
    body: CancelJob,
    key: Key,
    context: Identity,
    ota: Service,
) -> JobView:
    return await ota.cancel_job(
        tenant(context, Permission.OTA_MANAGE),
        context.principal.principal_id,
        str(job_id),
        key,
        body.reason,
    )
