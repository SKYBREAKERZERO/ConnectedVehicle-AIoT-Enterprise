"""Independent connections and real PostgreSQL locks, commits and process death."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from connected_vehicle.ota.campaign_retry import CampaignDatabaseBusy, database_retry
from connected_vehicle.ota.install_receipt import load_key
from enterprise_platform.database.runtime_security import verify_runtime_database_security
from enterprise_platform.errors.base import ConflictError
from tests.integration.day21.conftest import World

pytestmark = pytest.mark.integration


def signed(
    world: World,
    campaign: str,
    action: str,
    operation: str,
    body: dict[str, object] | None = None,
) -> dict[str, str]:
    path = world.settings.ota_install_receipt_keys_file
    assert path
    key_id, key = load_key(Path(path), world.tenant)
    payload = json.dumps(
        dict(
            protocol="cv-campaign/1",
            tenant_id=world.tenant,
            key_id=key_id,
            expires=int(time.time()) + 60,
            request=dict(
                campaign_id=campaign,
                command=action,
                operation_id=operation,
                actor="day21-test",
                reason="Day21 drill",
                body=body or {},
            ),
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return dict(p=payload, m=hmac.new(key, payload.encode(), hashlib.sha256).hexdigest())


async def wait_for_lock(world: World) -> None:
    async with asyncio.timeout(3):
        while True:
            async with world.admin.connect() as connection:
                waiting = await connection.scalar(
                    text(
                        "SELECT EXISTS(SELECT FROM pg_stat_activity "
                        "WHERE usename=:u AND wait_event_type='Lock')"
                    ),
                    dict(u=world.settings.database_username),
                )
            if waiting:
                return
            await asyncio.sleep(0.01)


async def test_runtime_authority_and_unique_migration_head(world: World) -> None:
    await verify_runtime_database_security(world.runtime, "application", tenant_id=world.tenant)
    async with world.admin.connect() as connection:
        assert await connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "b16f238d45ac"
        )
    for statement in (
        "UPDATE public.ota_jobs SET status='succeeded'",
        "UPDATE public.ota_campaigns SET status='completed'",
        "UPDATE public.ota_campaigns SET dispatch_owner=NULL",
        "UPDATE public.ota_campaign_targets SET dispatched=true",
        "SELECT * FROM ota_authority.receipt_keys",
    ):
        with pytest.raises(DBAPIError) as error:
            async with world.runtime.begin() as connection:
                await connection.execute(text(statement))
        assert getattr(error.value.orig, "sqlstate", None) == "42501"
    with pytest.raises(DBAPIError) as error:
        async with world.runtime.begin() as connection:
            await connection.execute(
                text("SELECT public.ota_campaign_claim('foreign',CAST(:o AS uuid),NULL,1)"),
                dict(o=str(uuid4())),
            )
    assert getattr(error.value.orig, "sqlstate", None) == "42501"


async def test_two_dispatchers_same_wave_and_replay_create_one_job(world: World) -> None:
    campaign = await world.campaign()
    operation = str(uuid4())
    await asyncio.gather(*(world.tick(campaign, operation) for _ in range(2)))
    await asyncio.gather(*(world.tick(campaign) for _ in range(2)))
    assert await world.count("ota_jobs") == 1
    assert await world.count("ota_audit_events") == 1
    view = await world.service.get(world.tenant, campaign)
    assert view.current_wave == 0 and view.job_count == 1 and view.status == "running"


async def test_wave_progression_never_skips_pending_work(world: World) -> None:
    campaign = await world.campaign()
    for wave in range(4):
        await asyncio.gather(world.tick(campaign), world.tick(campaign))
        view = await world.service.get(world.tenant, campaign)
        assert view.current_wave == wave and view.job_count == wave + 1
        await world.tick(campaign)
        assert (await world.service.get(world.tenant, campaign)).current_wave == wave
        async with world.admin.begin() as admin:
            await admin.execute(
                text(
                    "UPDATE ota_jobs SET status='succeeded',updated_at=clock_timestamp() "
                    "WHERE tenant_id=:t AND status='pending_verification'"
                ),
                dict(t=world.tenant),
            )
    assert (await world.tick(campaign)).status == "completed"
    assert await world.count("ota_jobs") == 4


async def test_dispatch_entrypoint_skips_busy_campaign_without_pausing(world: World) -> None:
    campaign = await world.campaign()
    async with world.admin.begin() as locked:
        await locked.execute(
            text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=campaign)
        )
        results = await asyncio.wait_for(
            asyncio.gather(
                world.service.dispatch(world.tenant, campaign),
                world.service.dispatch(world.tenant, campaign),
            ),
            2,
        )
    assert all(result.status == "running" and result.job_count == 0 for result in results)


async def test_process_crash_after_job_commit_can_replay(world: World) -> None:
    campaign, operation = await world.campaign(), str(uuid4())
    parameters = signed(world, campaign, "tick", operation, {"publisher_valid": True})
    script = """
import asyncio, os, asyncpg
async def main():
 c=await asyncpg.connect(host='127.0.0.1',port=int(os.environ['D21_PORT']),
   database='postgres',user=os.environ['D21_USER'],password='day21-runtime')
 await c.fetchval('SELECT public.ota_campaign_command($1,$2)',
   os.environ['D21_PAYLOAD'],os.environ['D21_MAC'])
 os._exit(91)
asyncio.run(main())
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        timeout=10,
        env=dict(
            os.environ,
            D21_PORT=str(world.settings.database_port),
            D21_USER=world.settings.database_username,
            D21_PAYLOAD=parameters["p"],
            D21_MAC=parameters["m"],
        ),
    )
    assert result.returncode == 91, result.stderr.decode()
    assert (await world.tick(campaign, operation)).job_count == 1
    assert await world.count("ota_jobs") == 1 and await world.count("ota_audit_events") == 1


async def test_skip_locked_allocates_disjoint_campaigns(world: World) -> None:
    first = await world.campaign(world.ecus[:2])
    second = await world.campaign(world.ecus[2:])
    async with world.admin.begin() as locked:
        await locked.execute(
            text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=first)
        )
        assert await asyncio.wait_for(world.service.claim(world.tenant, str(uuid4())), 1) == second
        assert await world.service.claim(world.tenant, str(uuid4()), first) is None
    owners = [str(uuid4()), str(uuid4())]
    claims = await asyncio.gather(*(world.service.claim(world.tenant, o, first) for o in owners))
    assert claims.count(first) == 1 and claims.count(None) == 1
    # Retrying a committed claim whose response was lost returns the same work.
    winner = owners[claims.index(first)]
    assert await world.service.claim(world.tenant, winner, first) == first


async def test_connection_death_rolls_back_uncommitted_claim(world: World) -> None:
    campaign = await world.campaign()
    connection = await world.runtime.connect()
    transaction = await connection.begin()
    try:
        pid = await connection.scalar(text("SELECT pg_backend_pid()"))
        assert (
            await connection.scalar(
                text("SELECT public.ota_campaign_claim(:t,CAST(:o AS uuid),:c,150)"),
                dict(t=world.tenant, o=str(uuid4()), c=campaign),
            )
            == campaign
        )
        async with world.admin.begin() as admin:
            assert await admin.scalar(text("SELECT pg_terminate_backend(:p)"), dict(p=pid))
    finally:
        with suppress(DBAPIError):
            await transaction.rollback()
        await connection.close()
    assert await world.service.claim(world.tenant, str(uuid4()), campaign) == campaign
    assert await world.count("ota_jobs") == 0


async def test_process_crash_after_claim_recovers_and_fences_old_owner(world: World) -> None:
    campaign = await world.campaign()
    old, new = str(uuid4()), str(uuid4())
    script = """
import asyncio, os, asyncpg
async def main():
 c=await asyncpg.connect(host='127.0.0.1',port=int(os.environ['D21_PORT']),
   database='postgres',user=os.environ['D21_USER'],password='day21-runtime')
 value=await c.fetchval('SELECT public.ota_campaign_claim($1,$2::uuid,$3,1)',
   os.environ['D21_TENANT'],__import__('uuid').UUID(os.environ['D21_OWNER']),os.environ['D21_CAMPAIGN'])
 assert value==os.environ['D21_CAMPAIGN']
 os._exit(91)
asyncio.run(main())
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        env=dict(
            os.environ,
            D21_PORT=str(world.settings.database_port),
            D21_USER=world.settings.database_username,
            D21_TENANT=world.tenant,
            D21_OWNER=old,
            D21_CAMPAIGN=campaign,
        ),
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 91, result.stderr.decode()
    assert await world.service.claim(world.tenant, new, campaign) is None
    await asyncio.sleep(1.1)
    assert await world.service.claim(world.tenant, new, campaign) == campaign
    await world.service.release(world.tenant, old, campaign)
    assert (await world.service.row(world.tenant, campaign))["dispatch_owner"] == UUID(new)
    with pytest.raises(ConflictError):
        await world.service.command(
            world.tenant,
            "day21-test",
            campaign,
            "tick",
            str(uuid4()),
            {"publisher_valid": True, "dispatch_owner": old},
            "Day21 drill",
        )
    assert await world.count("ota_jobs") == 0
    await world.service.command(
        world.tenant,
        "day21-test",
        campaign,
        "tick",
        str(uuid4()),
        {"publisher_valid": True, "dispatch_owner": new},
        "Day21 drill",
    )
    assert await world.count("ota_jobs") == 1


async def test_commit_then_http_response_loss_is_idempotent(world: World) -> None:
    campaign, operation = await world.campaign(), str(uuid4())
    committed = asyncio.Event()
    errors: list[Exception] = []

    async def lose_response(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            await world.tick(campaign, operation)
            # The DB COMMIT completed; drop the TCP connection before any HTTP response.
            committed.set()
        except Exception as exc:
            errors.append(exc)
            committed.set()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(lose_response, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"POST /dispatch HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 3) == b""
        writer.close()
        await writer.wait_closed()
    assert committed.is_set() and not errors
    recovered = await world.tick(campaign, operation)
    assert recovered.job_count == 1
    assert await world.count("ota_jobs") == 1 and await world.count("ota_audit_events") == 1


async def test_pause_serializes_before_waiting_tick(world: World) -> None:
    campaign = await world.campaign()
    async with world.runtime.begin() as pausing:
        await pausing.execute(
            text("SELECT public.ota_campaign_command(:p,:m)"),
            signed(world, campaign, "pause", str(uuid4())),
        )
        tick = asyncio.create_task(world.tick(campaign))
        await wait_for_lock(world)
        assert not tick.done()
    result = await tick
    assert result.status == "paused" and result.current_wave == -1
    assert await world.count("ota_jobs") == 0


async def test_pause_and_cancel_preserve_previously_claimed_jobs(world: World) -> None:
    campaign = await world.campaign()
    await world.tick(campaign)
    # Simulate the previously accepted device claim, using the isolated test administrator.
    async with world.admin.begin() as admin:
        await admin.execute(
            text("UPDATE ota_jobs SET status='downloading' WHERE tenant_id=:t"),
            dict(t=world.tenant),
        )
    for action in ("pause", "cancel"):
        await world.service.command(
            world.tenant, "day21-test", campaign, action, str(uuid4()), {}, "Day21 drill"
        )
        await world.tick(campaign)
        async with world.admin.connect() as admin:
            assert (
                await admin.scalar(
                    text("SELECT status FROM ota_jobs WHERE tenant_id=:t"), dict(t=world.tenant)
                )
                == "downloading"
            )
        assert await world.count("ota_jobs") == 1


async def test_lock_timeout_retries_are_bounded_and_do_not_pause(world: World) -> None:
    campaign = await world.campaign()
    async with world.admin.begin() as locked:
        await locked.execute(
            text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=campaign)
        )
        with pytest.raises(CampaignDatabaseBusy) as error:
            await asyncio.wait_for(world.tick(campaign), 9)
        assert error.value.sqlstate == "55P03" and error.value.attempts == 3
    assert (await world.service.get(world.tenant, campaign)).status == "running"
    assert await world.count("ota_jobs") == 0
    await world.tick(campaign)
    assert await world.count("ota_jobs") == 1


async def test_real_deadlock_rolls_back_and_retries_whole_transaction(world: World) -> None:
    first = await world.campaign(world.ecus[:2])
    second = await world.campaign(world.ecus[2:])
    acquired, competitor_locked = asyncio.Event(), asyncio.Event()
    attempts = 0

    async def operation() -> None:
        nonlocal attempts
        attempts += 1
        async with world.admin.begin() as connection:
            await connection.execute(text("SET LOCAL deadlock_timeout='50ms'"))
            await connection.execute(
                text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=first)
            )
            if attempts == 1:
                acquired.set()
                await competitor_locked.wait()
            await connection.execute(
                text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=second)
            )

    async def competitor() -> None:
        await acquired.wait()
        async with world.admin.begin() as connection:
            await connection.execute(text("SET LOCAL deadlock_timeout='5s'"))
            await connection.execute(
                text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=second)
            )
            competitor_locked.set()
            await connection.execute(
                text("SELECT 1 FROM ota_campaigns WHERE id=:c FOR UPDATE"), dict(c=first)
            )

    await asyncio.wait_for(asyncio.gather(database_retry(operation), competitor()), 5)
    assert attempts == 2
    assert await world.count("ota_jobs") == 0
