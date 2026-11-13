"""Classify release outcomes from a complete, ordered execution history."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import suppress
from enum import StrEnum
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import text

from connected_vehicle.ota.campaign_contracts import CampaignAction, CampaignState
from connected_vehicle.ota.campaign_service import CampaignService
from enterprise_platform.errors.base import ConflictError


class Outcome(StrEnum):
    BLOCKED = "BLOCKED"
    CANARY_PASSED = "CANARY_PASSED"
    RELEASE_ACCEPTED = "RELEASE_ACCEPTED"
    FAILED_RECOVERED = "FAILED_RECOVERED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


def classify(events: Sequence[str], wave_count: int) -> Outcome:
    if wave_count < 1 or not events or events[0] != "ADMITTED":
        return Outcome.BLOCKED
    tail = list(events[1:])
    passed = 0
    while tail and tail[0] == f"WAVE_PASSED:{passed + 1}" and passed < wave_count:
        tail.pop(0)
        passed += 1
    if tail and tail[0] in {"ECS_FAILED", "OTA_FAILED"}:
        mitigation = "ECS_REVERTED" if tail[0] == "ECS_FAILED" else "CAMPAIGN_PAUSED"
        if tail == [tail[0], "EXPANSION_STOPPED", mitigation, "RECONCILED"]:
            return Outcome.FAILED_RECOVERED
        return Outcome.RECOVERY_REQUIRED
    if passed == wave_count and tail == ["FINAL_VERIFIED"]:
        return Outcome.RELEASE_ACCEPTED
    if passed and not tail:
        return Outcome.CANARY_PASSED
    return Outcome.BLOCKED


async def pause_campaign(
    service: CampaignService, tenant: str, campaign: str, execution_id: str
) -> bool:
    """Stop new work using the same operation ID after a lost response."""
    if not execution_id:
        raise ValueError("Execution identity is required")
    operation = uuid5(NAMESPACE_URL, f"day42:{execution_id}:{tenant}:{campaign}:pause")
    view = await service.get(tenant, campaign)
    if view.status == CampaignState.RUNNING:
        # A concurrent pause or terminal transition may already have won.
        with suppress(ConflictError):
            await service.action(
                tenant,
                "day42-recovery",
                campaign,
                "pause",
                CampaignAction(operation_id=operation, reason="Day42 rollout circuit breaker"),
            )
    return (await service.get(tenant, campaign)).status == CampaignState.PAUSED


async def campaign_jobs_reconciled(service: CampaignService, tenant: str, campaign: str) -> bool:
    """Check native Campaign and Job state in a single database snapshot."""
    async with service.base.transaction(tenant) as session:
        return bool(
            await session.scalar(
                text("""
                    SELECT EXISTS (
                        SELECT FROM public.ota_campaigns c
                        WHERE c.tenant_id=:tenant AND c.id=:campaign AND c.status='paused'
                          AND NOT EXISTS (
                            SELECT FROM public.ota_campaign_targets t
                            LEFT JOIN public.ota_jobs j
                              ON j.tenant_id=t.tenant_id AND j.id=t.job_id
                            WHERE t.tenant_id=c.tenant_id AND t.campaign_id=c.id
                              AND (
                                (NOT t.dispatched AND j.id IS NOT NULL)
                                OR (t.dispatched AND (
                                  j.id IS NULL
                                  OR j.release_id IS DISTINCT FROM c.release_id
                                  OR j.ecu_id IS DISTINCT FROM t.ecu_id
                                  OR j.vehicle_id IS DISTINCT FROM t.vehicle_id
                                  OR j.status NOT IN ('succeeded', 'failed', 'cancelled')
                                ))
                              )
                          )
                    )
                    """),
                {"tenant": tenant, "campaign": campaign},
            )
        )
