"""Real PostgreSQL snapshots and real promtool; missing dependencies fail the gate."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.ota.campaign_metrics import CampaignMetrics, snapshot
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.observability.metrics import configure_metrics
from scripts.day12_evidence import source_commit
from scripts.day16_evidence import source_digest
from tests.integration.day21.conftest import World, docker
from tests.integration.day21.conftest import postgres as postgres
from tests.integration.day21.conftest import world as world
from tests.settings_helpers import isolated_settings

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module", autouse=True)
def test_source_stamp(record_testsuite_property: Callable[[str, object], None]) -> None:
    for name, value in {
        "day24_commit": source_commit(),
        "day24_run_id": os.environ.get("DAY24_EVIDENCE_RUN_ID", "local-day24"),
        "day24_source_sha256": source_digest(),
        "day24_rule_sha256": hashlib.sha256(
            (ROOT / "infra/observability/day24-campaign.yml").read_bytes()
        ).hexdigest(),
        "day24_scenario_sha256": hashlib.sha256(
            (ROOT / "tests/fixtures/day24/alerts.test.yml").read_bytes()
        ).hexdigest(),
    }.items():
        record_testsuite_property(name, value)


async def test_committed_campaign_wave_claim_job_metrics(world: World) -> None:
    campaign = await world.campaign()
    await world.tick(campaign)
    values = await snapshot(create_session_factory(world.runtime), world.tenant)
    assert values[("campaigns", "running")] == 1
    assert values[("jobs", "pending_verification")] == 1
    assert values[("waves", "current")] == 1
    assert values[("waves", "pending")] == 3
    assert values[("waves", "overdue")] == 0
    assert await world.count("ota_jobs") == 1


async def test_expired_lease_and_wave_recover(world: World) -> None:
    campaign = await world.campaign()
    await world.tick(campaign)
    owner = str(uuid4())
    assert await world.service.claim(world.tenant, owner, campaign) == campaign
    sessions = create_session_factory(world.runtime)
    assert (await snapshot(sessions, world.tenant))[("claims", "active")] == 1
    async with world.admin.begin() as admin:
        await admin.execute(
            text(
                "UPDATE ota_campaigns SET dispatch_until=now()-interval '1 second',"
                "wave_started_at=now()-interval '120 seconds' WHERE tenant_id=:t AND id=:c"
            ),
            {"t": world.tenant, "c": campaign},
        )
    values = await snapshot(sessions, world.tenant)
    assert values[("claims", "expired")] == 1 and values[("waves", "overdue")] == 1
    new_owner = str(uuid4())
    assert await world.service.claim(world.tenant, new_owner, campaign) == campaign
    await world.service.release(world.tenant, new_owner, campaign)
    async with world.admin.begin() as admin:
        await admin.execute(
            text("UPDATE ota_jobs SET status='succeeded' WHERE tenant_id=:t"),
            {"t": world.tenant},
        )
    values = await snapshot(sessions, world.tenant)
    assert values[("claims", "expired")] == 0 and values[("waves", "overdue")] == 0
    assert await world.count("ota_jobs") == 1


async def test_recent_job_failure_window(world: World) -> None:
    campaign = await world.campaign()
    await world.tick(campaign)
    sessions = create_session_factory(world.runtime)
    for age, expected in ((0, 1), (6, 0)):
        async with world.admin.begin() as admin:
            await admin.execute(
                text(
                    "UPDATE ota_jobs SET status='failed',"
                    "updated_at=now()-make_interval(mins=>:age) "
                    "WHERE tenant_id=:t"
                ),
                {"age": age, "t": world.tenant},
            )
        values = await snapshot(sessions, world.tenant)
        assert values[("jobs", "failed")] == 1
        assert values[("job_failures", "recent")] == expected


async def test_wrong_tenant_cannot_publish_business_metrics(world: World) -> None:
    await world.campaign()
    monitor = CampaignMetrics("different-tenant")
    body = await monitor.collect(create_session_factory(world.runtime))
    assert b"vehicle_ota_collection_success 0.0" in body
    assert b"vehicle_ota_campaigns" not in body
    with pytest.raises(ValueError, match="not bound"):
        await snapshot(create_session_factory(world.runtime), "different-tenant")


async def test_collection_lock_timeout_clears_stale_metrics(world: World) -> None:
    await world.campaign()
    monitor = CampaignMetrics(world.tenant)
    sessions = create_session_factory(world.runtime)
    assert b"vehicle_ota_campaigns" in await monitor.collect(sessions)
    async with world.admin.begin() as locked:
        await locked.execute(text("LOCK TABLE ota_campaigns IN ACCESS EXCLUSIVE MODE"))
        started = time.monotonic()
        failed = await monitor.collect(sessions)
        assert time.monotonic() - started < 3
        assert b"vehicle_ota_collection_success 0.0" in failed
        assert b"vehicle_ota_campaigns" not in failed
    assert b"vehicle_ota_collection_success 1.0" in await monitor.collect(sessions)


async def test_runtime_cannot_change_protected_state(world: World) -> None:
    await world.campaign()
    async with world.runtime.begin() as runtime:
        with pytest.raises(DBAPIError) as denied:
            await runtime.execute(text("UPDATE ota_campaigns SET status='completed'"))
        assert getattr(denied.value.orig, "sqlstate", None) == "42501"
    assert (await snapshot(create_session_factory(world.runtime), world.tenant))[
        ("campaigns", "running")
    ] == 1


async def test_authenticated_endpoint_exports_fixed_tenant_snapshot(world: World) -> None:
    campaign = await world.campaign()
    monitor = CampaignMetrics(world.tenant)
    app = FastAPI()

    async def extra() -> bytes:
        return await monitor.collect(create_session_factory(world.runtime))

    configure_metrics(app, isolated_settings(_env_file=None, metrics_token="x" * 64), extra=extra)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api"
    ) as client:
        assert (await client.get("/metrics")).status_code == 403
        response = await client.get("/metrics", headers={"Authorization": "Bearer " + "x" * 64})
    assert response.status_code == 200 and "vehicle_ota_campaigns" in response.text
    assert world.tenant not in response.text and campaign not in response.text
    assert all(ecu not in response.text for ecu in world.ecus)


def test_prometheus_alerts_fire_and_resolve() -> None:
    output = docker(
        "run",
        "--rm",
        "--entrypoint",
        "/bin/promtool",
        "-v",
        f"{ROOT}:/work:ro",
        "-w",
        "/work",
        "prom/prometheus:v3.5.0",
        "test",
        "rules",
        "tests/fixtures/day24/alerts.test.yml",
    )
    assert "SUCCESS" in output
