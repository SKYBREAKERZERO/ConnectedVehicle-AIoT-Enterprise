from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from enterprise_platform.database.engine import build_database_url, create_database_engine
from enterprise_platform.database.migration_guard import MIGRATION_LOCK_KEY
from tests.e2e.test_independent_runtimes import ROOT, docker
from tests.integration.day12.conftest import evidence
from tests.integration.day12.migration_support import (
    DAY11,
    HEAD,
    LEGACY,
    OWNER,
    TABLES,
    Harness,
    catalog_diff,
    runtime_engine,
    seed,
    snapshot,
    start_harness,
)


def shared_upgrade(connection: Connection) -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture(scope="module")
def rehearsal(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Harness]:
    harness = start_harness(tmp_path_factory.mktemp("day11-release-backup"))
    try:
        harness.source_snapshot = asyncio.run(released_backup(harness))
        yield harness
    finally:
        docker("rm", "-f", harness.container)


async def released_backup(harness: Harness) -> dict[str, Any]:
    settings = harness.database("day11_source")
    harness.upgrade(settings, release=True)
    harness.grants(settings, release=True)
    engine = create_database_engine(settings)
    try:
        async with engine.begin() as connection:
            await seed(connection)
        old = await snapshot(engine)
        assert old["revision"] == LEGACY
        harness.dump(settings)
        return old
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_released_backup_and_fresh_database_security_converge(rehearsal: Harness) -> None:
    old = rehearsal.source_snapshot
    assert old is not None
    restore_started = datetime.now(UTC).isoformat()
    restore_tick = time.monotonic()
    restored_settings = rehearsal.restore("day12_restored")
    restored = create_database_engine(restored_settings)
    fresh_settings = rehearsal.database("day12_fresh")
    fresh = create_database_engine(fresh_settings)
    try:
        before = await snapshot(restored)
        restore_seconds = time.monotonic() - restore_tick
        restore_finished = datetime.now(UTC).isoformat()
        evidence("migration-restore-diff", catalog_diff(old, before))
        assert before["catalog"] == old["catalog"]
        assert before["data"] == old["data"]
        assert before["sequence_state"] == old["sequence_state"]
        started = datetime.now(UTC).isoformat()
        tick = time.monotonic()
        rehearsal.upgrade(restored_settings)
        elapsed = time.monotonic() - tick
        finished = datetime.now(UTC).isoformat()
        after = await snapshot(restored)
        assert after["revision"] == HEAD and after["data"] == before["data"]
        assert after["sequence_state"] == before["sequence_state"]
        for section in (
            "roles",
            "memberships",
            "database_grants",
            "schema_grants",
            "default_grants",
            "sequences",
        ):
            assert after["catalog"][section] == before["catalog"][section]
        assert [
            row
            for row in after["catalog"]["indexes"]
            if row["tablename"] != "runtime_tenant_bindings"
        ] == before["catalog"]["indexes"]
        for section in ("tables", "columns", "constraints", "table_grants", "column_grants"):
            original = [row for row in before["catalog"][section] if row["relname"] in TABLES]
            current = [row for row in after["catalog"][section] if row["relname"] in TABLES]
            assert original == current
        for section in ("functions", "function_grants"):
            assert [
                row for row in after["catalog"][section] if row["proname"] == "outbox_event_tenant"
            ] == before["catalog"][section]
        rehearsal.upgrade(fresh_settings)
        rehearsal.grants(fresh_settings)
        clean = await snapshot(fresh)
        assert clean["catalog"] == after["catalog"]
        repeat_started = datetime.now(UTC).isoformat()
        tick = time.monotonic()
        rehearsal.upgrade(restored_settings)
        repeat_seconds = time.monotonic() - tick
        repeat_finished = datetime.now(UTC).isoformat()
        repeated = await snapshot(restored)
        assert repeated == after
        async with restored.connect() as connection:
            role = dict(
                (
                    await connection.execute(
                        text("""SELECT current_user AS name,
                rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication
                FROM pg_roles WHERE rolname=current_user""")
                    )
                )
                .mappings()
                .one()
            )
            assert role["name"] == OWNER and not any(
                value for key, value in role.items() if key != "name"
            )
            with pytest.raises(DBAPIError):
                await connection.execute(text("CREATE ROLE forbidden_migration_role"))
            await connection.rollback()
        assert set(before["data"]) == set(TABLES)
        assert all(table["rows"] > 0 for table in before["data"].values())
        assert all(len(table["tenant_row_counts"]) == 2 for table in before["data"].values())
        assert all(count == 0 for count in before["relationships"].values())
        evidence(
            "12a-migrations",
            {
                "fresh": "passed",
                "existing": "passed",
                "repeat_upgrade": "no changes",
                "existing_rows": "preserved",
                "policies": "identical",
                "source": {
                    "kind": "released-day11-pg-dump",
                    "release_commit": DAY11,
                    "revision": LEGACY,
                    "backup_sha256": rehearsal.backup_sha256,
                    "synthetic_fixture": True,
                },
                "migration_identity": role,
                "steps": [
                    {
                        "name": "restored",
                        "revision": before["revision"],
                        "schema_sha256": before["catalog_sha256"],
                        "started_at_utc": restore_started,
                        "finished_at_utc": restore_finished,
                        "seconds": restore_seconds,
                    },
                    {
                        "name": "upgraded",
                        "revision": after["revision"],
                        "started_at_utc": started,
                        "finished_at_utc": finished,
                        "seconds": elapsed,
                        "schema_sha256": after["catalog_sha256"],
                    },
                    {
                        "name": "repeat",
                        "revision": repeated["revision"],
                        "seconds": repeat_seconds,
                        "started_at_utc": repeat_started,
                        "finished_at_utc": repeat_finished,
                        "schema_sha256": repeated["catalog_sha256"],
                    },
                ],
                "historical_data": before["data"],
                "relationship_violations": before["relationships"],
                "catalog_before": before["catalog"],
                "catalog_after": after["catalog"],
                "schema_diff": catalog_diff(before, after),
                "security_and_schema_converged": True,
                "release_raw_constraints": old["raw_constraints"],
                "restored_raw_constraints": before["raw_constraints"],
            },
        )
    finally:
        await restored.dispose()
        await fresh.dispose()


@pytest.mark.integration
async def test_sql_failure_rolls_back_ddl_revision_and_data_then_retry(rehearsal: Harness) -> None:
    settings = rehearsal.restore("day12_failure")
    engine = create_database_engine(settings)
    before = await snapshot(engine)
    injected: list[str] = []

    def fail_sql(
        connection: Connection,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> tuple[str, Any]:
        if statement.startswith("CREATE POLICY tenant_guard ON remote_commands"):
            injected.append("after binding table/function and vehicles policy DDL")
            return "SELECT 1/0", parameters
        return statement, parameters

    try:
        event.listen(engine.sync_engine, "before_cursor_execute", fail_sql, retval=True)
        try:
            async with engine.connect() as connection:
                with pytest.raises(DBAPIError) as failed:
                    await connection.run_sync(shared_upgrade)
                assert getattr(failed.value.orig, "sqlstate", None) == "22012"
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", fail_sql)
        assert injected
        rolled_back = await snapshot(engine)
        assert rolled_back == before
        rehearsal.upgrade(settings)
        after = await snapshot(engine)
        assert after["revision"] == HEAD and after["data"] == before["data"]
        evidence(
            "migration-failure-retry",
            {
                "sqlstate": "22012",
                "injected_after": injected[0],
                "revision_before": before["revision"],
                "revision_after_failure": rolled_back["revision"],
                "schema_before_sha256": before["catalog_sha256"],
                "schema_after_failure_sha256": rolled_back["catalog_sha256"],
                "data_before": before["data"],
                "data_after_failure": rolled_back["data"],
                "retry_revision": after["revision"],
                "rollback_complete": True,
                "retry_succeeded": True,
            },
        )
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_large_table_lock_timeout_and_runtime_compatibility(rehearsal: Harness) -> None:
    settings = rehearsal.restore("day12_large")
    admin = create_database_engine(settings)
    runtime = runtime_engine(settings)
    try:
        async with admin.begin() as connection:
            await connection.execute(
                text("""INSERT INTO telemetry_samples SELECT
        md5('bulk-'||g)::uuid::text,v.tenant_id,v.id,'2026-10-01','2026-10-01',
        json_build_object('speed_kph',g%100,'battery_percent',80,'temperature_c',20) FROM
        generate_series(1,50000) g CROSS JOIN LATERAL ( SELECT id,tenant_id FROM vehicles
        WHERE tenant_id=CASE WHEN g%2=0 THEN 'history-a' ELSE 'history-b' END ORDER BY id
        LIMIT 1) v""")
            )
        before = await snapshot(admin)
        assert before["data"]["telemetry_samples"]["rows"] == 50012
        async with runtime.connect() as reader:
            await reader.execute(text("SELECT set_config('app.tenant_id','history-a',true)"))
            assert await reader.scalar(text("SELECT count(*) FROM vehicles")) == 3
            fast = settings.model_copy(update={"migration_lock_timeout_seconds": 0.5})
            tick = time.monotonic()
            waiting = asyncio.create_task(
                asyncio.to_thread(rehearsal.upgrade, fast, expected=False)
            )
            observed_lock = False
            while not waiting.done():
                async with admin.connect() as observer:
                    observed_lock |= bool(
                        await observer.scalar(
                            text("""SELECT EXISTS (
                        SELECT FROM pg_stat_activity WHERE datname=current_database()
                        AND application_name='connected-vehicle-migration'
                        AND wait_event_type='Lock')""")
                        )
                    )
                await asyncio.sleep(0.02)
            result = await waiting
            wait_seconds = time.monotonic() - tick
            assert result.returncode != 0 and b"lock timeout" in result.stderr
            assert observed_lock
            assert wait_seconds < 15
            await reader.execute(
                text("""INSERT INTO telemetry_samples VALUES
                ('00000000-0000-0000-0000-000000000099','history-a',
                (SELECT id FROM vehicles LIMIT 1),'2026-10-01','2026-10-01','{}')""")
            )
            await reader.rollback()
        assert await snapshot(admin) == before
        samples: list[float] = []

        upgrade_task = asyncio.create_task(asyncio.to_thread(rehearsal.upgrade, settings))

        async def reader_writer() -> None:
            while not upgrade_task.done() or len(samples) < 10:
                tick = time.monotonic()
                async with runtime.begin() as connection:
                    await connection.execute(
                        text("SELECT set_config('app.tenant_id','history-a',true)")
                    )
                    assert await connection.scalar(text("SELECT count(*) FROM vehicles")) == 3
                    await connection.execute(
                        text("UPDATE remote_commands SET status=status WHERE tenant_id='history-a'")
                    )
                    assert (
                        await connection.scalar(
                            text("SELECT count(*) FROM vehicles WHERE tenant_id='history-b'")
                        )
                        == 0
                    )
                samples.append(time.monotonic() - tick)
                await asyncio.sleep(0.01)

        tick = time.monotonic()
        await asyncio.gather(upgrade_task, reader_writer())
        duration = time.monotonic() - tick
        assert duration < 30
        after = await snapshot(admin)
        assert after["revision"] == HEAD and after["data"] == before["data"]
        evidence(
            "migration-scale-locks",
            {
                "rows": before["data"],
                "lock_timeout_seconds": 0.5,
                "observed_timeout_elapsed_seconds": wait_seconds,
                "lock_timeout_rolled_back": True,
                "postgres_lock_wait_observed": observed_lock,
                "migration_elapsed_seconds": duration,
                "runtime_read_write_transactions": len(samples),
                "runtime_max_seconds": max(samples),
                "data_preserved": True,
                "scope": "50000-row local fixture; not a production capacity guarantee",
            },
        )
    finally:
        await runtime.dispose()
        await admin.dispose()


@pytest.mark.integration
async def test_migration_serialization_and_shared_timeout(rehearsal: Harness) -> None:
    settings = rehearsal.restore("day12_serialized")
    engine = create_database_engine(settings)
    timeout_settings = rehearsal.restore("day12_shared_timeout")
    timeout_engine = create_database_engine(timeout_settings)
    tasks: list[asyncio.Task[Any]] = []
    try:
        before = await snapshot(engine)
        async with engine.connect() as holder:
            await holder.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY}
            )
            generous = settings.model_copy(update={"migration_lock_timeout_seconds": 20})
            tasks = [
                asyncio.create_task(asyncio.to_thread(rehearsal.upgrade, generous))
                for _ in range(2)
            ]
            deadline = time.monotonic() + 15
            waiters = 0
            while waiters != 2 and time.monotonic() < deadline:
                async with engine.connect() as observer:
                    waiters = int(
                        await observer.scalar(
                            text("""SELECT count(*) FROM pg_locks l
                        JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database()
                        AND a.application_name='connected-vehicle-migration'
                        AND l.locktype='advisory' AND NOT l.granted""")
                        )
                        or 0
                    )
                if any(task.done() for task in tasks):
                    break
                await asyncio.sleep(0.02)
            assert waiters == 2
            await holder.rollback()
        completed = await asyncio.gather(*tasks)
        after = await snapshot(engine)
        assert after["revision"] == HEAD and after["data"] == before["data"]
        async with engine.connect() as connection:
            released = await connection.scalar(
                text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY}
            )
            assert released is True
        timeout_before = await snapshot(timeout_engine)

        def slow_sql(
            connection: Connection,
            cursor: Any,
            statement: str,
            parameters: Any,
            context: Any,
            executemany: bool,
        ) -> tuple[str, Any]:
            if statement.startswith("CREATE POLICY tenant_guard ON remote_commands"):
                return "SELECT pg_sleep(2)", parameters
            return statement, parameters

        fast = timeout_settings.model_copy(update={"migration_statement_timeout_seconds": 0.2})
        event.listen(timeout_engine.sync_engine, "before_cursor_execute", slow_sql, retval=True)
        try:
            async with timeout_engine.connect() as connection:
                original = tuple(
                    (
                        await connection.execute(
                            text("""SELECT
                    current_setting('statement_timeout'),current_setting('lock_timeout'),
                    current_setting('application_name')""")
                        )
                    ).one()
                )
                await connection.rollback()
                tick = time.monotonic()
                with (
                    patch("enterprise_platform.config.settings.get_settings", return_value=fast),
                    pytest.raises(DBAPIError) as failure,
                ):
                    await connection.run_sync(shared_upgrade)
                elapsed = time.monotonic() - tick
                sqlstate = getattr(failure.value.orig, "sqlstate", None)
                assert sqlstate == "57014" and elapsed < 5
                restored = tuple(
                    (
                        await connection.execute(
                            text("""SELECT
                    current_setting('statement_timeout'),current_setting('lock_timeout'),
                    current_setting('application_name')""")
                        )
                    ).one()
                )
                assert restored == original
                assert (
                    await connection.scalar(
                        text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY}
                    )
                    is True
                )
        finally:
            event.remove(timeout_engine.sync_engine, "before_cursor_execute", slow_sql)
        assert await snapshot(timeout_engine) == timeout_before
        async with timeout_engine.connect() as connection:
            connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
            with pytest.raises(ValueError, match="transactional"):
                await connection.run_sync(shared_upgrade)
        assert await snapshot(timeout_engine) == timeout_before
        rehearsal.upgrade(timeout_settings)
        retried = await snapshot(timeout_engine)
        assert retried["catalog"] == after["catalog"]
        assert retried["data"] == timeout_before["data"]
        evidence(
            "migration-guards",
            {
                "concurrent_upgrade_exit_codes": [result.returncode for result in completed],
                "advisory_waiters_observed": waiters,
                "advisory_lock_released": released,
                "data_preserved": True,
                "shared_timeout_sqlstate": sqlstate,
                "shared_timeout_elapsed_seconds": elapsed,
                "shared_settings_restored": restored == original,
                "timeout_rollback_complete": True,
                "autocommit_rejected": True,
                "retry_succeeded": True,
            },
        )
    finally:
        # Finish thread-backed commands before removing their dedicated container.
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await timeout_engine.dispose()
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize("isolation", ["AUTOCOMMIT", "REPEATABLE READ", "SERIALIZABLE"])
async def test_engine_default_isolation_cannot_bypass_guard(
    rehearsal: Harness, isolation: str
) -> None:
    settings = rehearsal.restore("day12_unsafe_" + isolation.lower().replace(" ", "_"))
    engine = create_database_engine(settings)
    unsafe = create_async_engine(build_database_url(settings), isolation_level=isolation)
    try:
        before = await snapshot(engine)
        async with unsafe.connect() as connection:
            synchronous = connection.sync_connection
            assert synchronous is not None
            assert "isolation_level" not in synchronous.get_execution_options()
            with pytest.raises(ValueError, match="transactional|READ COMMITTED"):
                await connection.run_sync(shared_upgrade)
        assert await snapshot(engine) == before
    finally:
        await unsafe.dispose()
        await engine.dispose()
