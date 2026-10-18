"""Operator-only campaign intent and rollout controls."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request

from apps.api.routers.device_data import Identity, Sessions, tenant
from connected_vehicle.ota.artifacts import ArtifactVerifier
from connected_vehicle.ota.campaign_contracts import (
    CampaignAction,
    CampaignCreate,
    CampaignFreeze,
    CampaignTarget,
    CampaignView,
)
from connected_vehicle.ota.campaign_service import CampaignService
from connected_vehicle.ota.service import OTAService
from enterprise_platform.config.settings import get_settings
from enterprise_platform.security.permissions import Permission

router = APIRouter(prefix="/v2/ota/campaigns", tags=["OTA Campaign v1"])
Limit = Annotated[int, Query(ge=1, le=100)]


def service(request: Request, sessions: Sessions) -> CampaignService:
    if not hasattr(request.app.state, "ota_artifacts"):
        request.app.state.ota_artifacts = ArtifactVerifier(get_settings())
    return CampaignService(OTAService(sessions), request.app.state.ota_artifacts)


Service = Annotated[CampaignService, Depends(service)]


@router.post("", status_code=201, operation_id="createOTACampaign")
async def create(body: CampaignCreate, context: Identity, campaigns: Service) -> CampaignView:
    return await campaigns.create(
        tenant(context, Permission.OTA_MANAGE), context.principal.principal_id, body
    )


@router.get("", operation_id="listOTACampaigns")
async def listing(
    context: Identity, campaigns: Service, limit: Limit = 50, after: UUID | None = None
) -> list[CampaignView]:
    return await campaigns.listing(
        tenant(context, Permission.OTA_READ), str(after) if after else "", limit
    )


@router.get("/{campaign_id}", operation_id="getOTACampaign")
async def get(campaign_id: UUID, context: Identity, campaigns: Service) -> CampaignView:
    return await campaigns.get(tenant(context, Permission.OTA_READ), str(campaign_id))


@router.get("/{campaign_id}/targets", operation_id="listOTACampaignTargets")
async def targets(
    campaign_id: UUID,
    context: Identity,
    campaigns: Service,
    limit: Limit = 100,
    after: UUID | None = None,
) -> list[CampaignTarget]:
    return await campaigns.targets(
        tenant(context, Permission.OTA_READ), str(campaign_id), str(after) if after else "", limit
    )


@router.post("/{campaign_id}/freeze", operation_id="freezeOTACampaign")
async def freeze(
    campaign_id: UUID, body: CampaignFreeze, context: Identity, campaigns: Service
) -> CampaignView:
    return await campaigns.freeze(
        tenant(context, Permission.OTA_MANAGE),
        context.principal.principal_id,
        str(campaign_id),
        body,
    )


@router.post("/{campaign_id}/actions/{action}", operation_id="controlOTACampaign")
async def action(
    campaign_id: UUID, action: str, body: CampaignAction, context: Identity, campaigns: Service
) -> CampaignView:
    from enterprise_platform.errors.base import InvalidRequestError

    if action not in {"start", "pause", "resume", "cancel"}:
        raise InvalidRequestError("Unsupported campaign action")
    return await campaigns.action(
        tenant(context, Permission.OTA_MANAGE),
        context.principal.principal_id,
        str(campaign_id),
        action,
        body,
    )
