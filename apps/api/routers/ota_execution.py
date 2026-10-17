from __future__ import annotations

from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import text

from apps.api.routers.device_data import Identity, Sessions, device, tenant
from connected_vehicle.ota.artifacts import ArtifactVerifier
from connected_vehicle.ota.device_proof import verify_proof
from connected_vehicle.ota.execution_contracts import (
    ClaimRequest,
    ClaimResult,
    ExecutionECUView,
    ExecutionView,
    OTAReport,
    VerificationRequest,
)
from connected_vehicle.ota.execution_service import OTAExecutionService
from enterprise_platform.config.settings import get_settings
from enterprise_platform.errors.base import ConflictError
from enterprise_platform.security.permissions import Permission

router = APIRouter(tags=["OTA Execution v2"])


def service(request: Request, sessions: Sessions) -> OTAExecutionService:
    if not hasattr(request.app.state, "ota_artifacts"):
        request.app.state.ota_artifacts = ArtifactVerifier(get_settings())
    return OTAExecutionService(sessions, request.app.state.ota_artifacts)


Service = Annotated[OTAExecutionService, Depends(service)]


async def ecu_device(
    request: Request, context: Identity, execution: Service, vehicle: UUID, ecu: UUID
) -> str:
    bound = device(context, vehicle, Permission.OTA_EXECUTE)
    path = get_settings().ota_device_keys_file
    if not path:
        raise HTTPException(403, "Independent ECU installation proof required")
    try:
        nonce = verify_proof(
            Path(path),
            method=request.method,
            path=request.url.path,
            body=await request.body(),
            tenant=bound,
            vehicle=str(vehicle),
            ecu=str(ecu),
            device=context.principal.principal_id,
            headers=request.headers,
        )
        async with execution.base.transaction(bound) as session:
            await session.execute(
                text("SELECT public.ota_accept_device_nonce(:tenant,:device,:nonce)"),
                {"tenant": bound, "device": context.principal.principal_id, "nonce": nonce},
            )
    except (OSError, ValueError, ConflictError) as exc:
        raise HTTPException(403, "Invalid, expired, replayed or unauthorized ECU proof") from exc
    return bound


@router.get("/v2/vehicles/{vehicle_id}/ecus/{ecu_id}", operation_id="getOTAInventoryV2")
async def inventory(
    vehicle_id: UUID, ecu_id: UUID, context: Identity, execution: Service
) -> ExecutionECUView:
    return await execution.inventory(
        tenant(context, Permission.OTA_READ), str(vehicle_id), str(ecu_id)
    )


@router.get(
    "/v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/next", operation_id="pollOTAExecutionV2"
)
async def available(
    vehicle_id: UUID, ecu_id: UUID, context: Identity, execution: Service, request: Request
) -> list[ExecutionView]:
    return await execution.available(
        await ecu_device(request, context, execution, vehicle_id, ecu_id),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
    )


@router.get("/v2/ota/jobs/{job_id}", operation_id="getOTAExecutionV2")
async def read(job_id: UUID, context: Identity, execution: Service) -> ExecutionView:
    return await execution.read(tenant(context, Permission.OTA_READ), str(job_id))


@router.post("/v2/ota/jobs/{job_id}/verify", operation_id="verifyOTAArtifactV2")
async def verify(
    job_id: UUID,
    body: VerificationRequest,
    context: Identity,
    execution: Service,
) -> ExecutionView:
    return await execution.verify(
        tenant(context, Permission.OTA_MANAGE), context.principal.principal_id, str(job_id), body
    )


@router.post(
    "/v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/{job_id}/claim",
    operation_id="claimOTAExecutionV2",
)
async def claim(
    vehicle_id: UUID,
    ecu_id: UUID,
    job_id: UUID,
    body: ClaimRequest,
    context: Identity,
    execution: Service,
    request: Request,
) -> ClaimResult:
    return await execution.claim(
        await ecu_device(request, context, execution, vehicle_id, ecu_id),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
        str(job_id),
        body,
    )


@router.get(
    "/v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/{job_id}/artifact",
    operation_id="downloadOTAArtifactV2",
)
async def download(
    vehicle_id: UUID,
    ecu_id: UUID,
    job_id: UUID,
    context: Identity,
    execution: Service,
    request: Request,
    claim_token: Annotated[UUID, Header(alias="X-OTA-Claim")],
) -> Response:
    data = await execution.artifact(
        await ecu_device(request, context, execution, vehicle_id, ecu_id),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
        str(job_id),
        str(claim_token),
    )
    return Response(
        data, media_type="application/octet-stream", headers={"Cache-Control": "no-store"}
    )


@router.post(
    "/v2/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs/{job_id}/reports",
    operation_id="reportOTAExecutionV2",
)
async def report(
    vehicle_id: UUID,
    ecu_id: UUID,
    job_id: UUID,
    body: OTAReport,
    context: Identity,
    execution: Service,
    request: Request,
) -> ExecutionView:
    return await execution.report(
        await ecu_device(request, context, execution, vehicle_id, ecu_id),
        context.principal.principal_id,
        str(vehicle_id),
        str(ecu_id),
        str(job_id),
        body,
    )
