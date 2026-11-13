from __future__ import annotations

import pytest
from sqlalchemy import text

from connected_vehicle.ota.campaign_contracts import CampaignState
from scripts.day42_recovery import campaign_jobs_reconciled, pause_campaign
from tests.integration.day21.conftest import World

pytestmark = pytest.mark.integration


async def test_day42_pause_replay_and_native_job_reconciliation(world: World) -> None:
    campaign = await world.campaign()
    opened = await world.tick(campaign)
    assert opened.current_wave == 0 and opened.job_count == 1
    assert await pause_campaign(world.service, world.tenant, campaign, "execution-1")
    count = await world.count("ota_campaign_events")
    assert await pause_campaign(world.service, world.tenant, campaign, "execution-1")
    assert await world.count("ota_campaign_events") == count
    assert not await campaign_jobs_reconciled(world.service, world.tenant, campaign)
    async with world.admin.begin() as connection:
        await connection.execute(
            text("UPDATE public.ota_jobs SET status='succeeded' WHERE tenant_id=:tenant"),
            {"tenant": world.tenant},
        )
    assert await campaign_jobs_reconciled(world.service, world.tenant, campaign)
    current = await world.tick(campaign)
    assert current.status == CampaignState.PAUSED
    assert current.current_wave == 0 and current.job_count == 1 and current.succeeded == 1
    assert not await campaign_jobs_reconciled(world.service, "other-tenant", campaign)
