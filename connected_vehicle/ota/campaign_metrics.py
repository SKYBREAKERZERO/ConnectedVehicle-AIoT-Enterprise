"""Read-only, fixed-tenant campaign snapshots; no identifiers in metric labels."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping

from prometheus_client import CollectorRegistry, Gauge, generate_latest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

STATES = {
    "campaigns": ("draft", "frozen", "running", "paused", "completed", "cancelled"),
    "waves": ("pending", "current", "overdue"),
    "claims": ("active", "expired"),
    "job_failures": ("recent",),
    "jobs": (
        "pending_verification",
        "verified",
        "downloading",
        "installing",
        "succeeded",
        "failed",
        "cancelled",
    ),
}

SNAPSHOT = """
WITH c AS MATERIALIZED (
  SELECT * FROM public.ota_campaigns WHERE tenant_id=:tenant
), t AS MATERIALIZED (
  SELECT t.* FROM public.ota_campaign_targets t JOIN c
    ON c.tenant_id=t.tenant_id AND c.id=t.campaign_id
), j AS MATERIALIZED (
  SELECT j.* FROM public.ota_jobs j JOIN t
    ON j.tenant_id=t.tenant_id AND j.id=t.job_id WHERE t.dispatched
), open_wave AS (
  SELECT c.* FROM c WHERE c.status='running' AND c.current_wave>=0 AND EXISTS (
    SELECT FROM t WHERE t.campaign_id=c.id AND t.wave=c.current_wave AND
      (NOT t.dispatched OR NOT EXISTS (
        SELECT FROM j WHERE j.id=t.job_id AND j.status IN ('succeeded','failed','cancelled')
      ))
  )
)
SELECT 'campaigns' AS category,status AS state,count(*) AS count FROM c GROUP BY status
UNION ALL SELECT 'jobs',status,count(*) FROM j GROUP BY status
UNION ALL SELECT 'job_failures','recent',count(*) FROM j
  WHERE status='failed' AND updated_at>=CURRENT_TIMESTAMP-interval '5 minutes'
UNION ALL SELECT 'claims','active',count(*) FROM c
  WHERE status='running' AND dispatch_owner IS NOT NULL AND dispatch_until>CURRENT_TIMESTAMP
UNION ALL SELECT 'claims','expired',count(*) FROM c
  WHERE status='running' AND dispatch_owner IS NOT NULL AND dispatch_until<=CURRENT_TIMESTAMP
UNION ALL SELECT 'waves','current',count(*) FROM c WHERE status='running' AND current_wave>=0
UNION ALL SELECT 'waves','pending',count(DISTINCT (t.campaign_id,t.wave)) FROM t JOIN c
  ON c.id=t.campaign_id WHERE c.status IN ('frozen','running','paused') AND t.wave>c.current_wave
UNION ALL SELECT 'waves','overdue',count(*) FROM open_wave
  WHERE wave_started_at+make_interval(secs=>wave_timeout_seconds)<CURRENT_TIMESTAMP
"""


async def snapshot(
    sessions: async_sessionmaker[AsyncSession], tenant: str
) -> dict[tuple[str, str], int]:
    if not tenant or tenant != tenant.strip() or len(tenant) > 255:
        raise ValueError("Fixed monitoring tenant required")
    async with asyncio.timeout(3), sessions() as session, session.begin():
        await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        await session.execute(text("SET LOCAL statement_timeout='1500ms'"))
        await session.execute(text("SET LOCAL lock_timeout='500ms'"))
        binding = await session.scalar(text("SELECT public.runtime_tenant_binding()"))
        if binding != tenant:
            raise ValueError("Monitoring identity is not bound to the configured tenant")
        rows = (await session.execute(text(SNAPSHOT), {"tenant": tenant})).mappings()
        result = {(str(row["category"]), str(row["state"])): int(row["count"]) for row in rows}
        if any(
            category not in STATES or state not in STATES[category] or count < 0
            for (category, state), count in result.items()
        ):
            raise ValueError("Unexpected campaign metric state")
        return result


class CampaignMetrics:
    def __init__(self, tenant: str | None) -> None:
        self.tenant = tenant
        self.last_success = 0.0
        self.lock = asyncio.Lock()

    async def collect(self, sessions: async_sessionmaker[AsyncSession] | None) -> bytes:
        async with asyncio.timeout(4), self.lock:
            started = time.monotonic()
            values: Mapping[tuple[str, str], int] | None = None
            if self.tenant:
                try:
                    if sessions is None:
                        raise ValueError("Monitoring sessions unavailable")
                    values = await snapshot(sessions, self.tenant)
                    self.last_success = time.time()
                except Exception:
                    # Do not emit cached business gauges or exception/SQL/credential labels.
                    values = None
            registry = CollectorRegistry()
            for name, value in (
                ("enabled", float(bool(self.tenant))),
                ("collection_success", float(values is not None)),
                ("last_success_timestamp_seconds", self.last_success),
                ("collection_duration_seconds", time.monotonic() - started),
            ):
                Gauge(f"vehicle_ota_{name}", f"Campaign snapshot {name}", registry=registry).set(
                    value
                )
            if values is not None:
                for category, states in STATES.items():
                    gauge = Gauge(
                        f"vehicle_ota_{category}",
                        "Committed campaign snapshot count",
                        ["state"],
                        registry=registry,
                    )
                    for state in states:
                        gauge.labels(state).set(values.get((category, state), 0))
            return generate_latest(registry)
