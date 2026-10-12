from __future__ import annotations

import subprocess
import sys

import pytest
from sqlalchemy import text

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine
from tests.integration.day12.conftest import evidence, migration_environment


@pytest.mark.integration
async def test_new_and_existing_database_migrate_identically(local_environment: Settings) -> None:
    catalog = text("""SELECT c.relname,p.polname,p.polpermissive,p.polcmd::text,
        pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)
        FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid ORDER BY c.relname,p.polname""")
    snapshots = []
    for name, baseline in (("day12_fresh", "head"), ("day12_legacy", "a37e610c952d")):
        administrator = create_database_engine(local_environment)
        try:
            async with administrator.connect() as connection:
                await connection.execution_options(isolation_level="AUTOCOMMIT")
                await connection.execute(text(f"CREATE DATABASE {name}"))
        finally:
            await administrator.dispose()
        settings = local_environment.model_copy(update={"database_name": name})
        environment = migration_environment(settings)
        environment.pop("DATABASE_TENANT_ID", None)
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", baseline],
            env=environment,
            check=True,
            capture_output=True,
        )
        engine = create_database_engine(settings)
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    text("""INSERT INTO vehicles VALUES
                    ('00000000-0000-0000-0000-000000000001','ABC12345678901234',
                    'migration-tenant','active',now(),now())""")
                )
                before = (await connection.execute(text("SELECT * FROM vehicles"))).all()
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                env=environment,
                check=True,
                capture_output=True,
            )
            async with engine.connect() as connection:
                first = (await connection.execute(catalog)).all()
                assert (await connection.execute(text("SELECT * FROM vehicles"))).all() == before
                assert (
                    await connection.scalar(text("SELECT version_num FROM alembic_version"))
                    == "b48f720da63e"
                )
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                env=environment,
                check=True,
                capture_output=True,
            )
            async with engine.connect() as connection:
                assert (await connection.execute(catalog)).all() == first
                assert (await connection.execute(text("SELECT * FROM vehicles"))).all() == before
            assert len(first) == 10
            snapshots.append(first)
        finally:
            await engine.dispose()
    assert snapshots[0] == snapshots[1]
    evidence(
        "12a-migrations",
        {
            "fresh": "passed",
            "existing": "passed",
            "repeat_upgrade": "no changes",
            "existing_rows": "preserved",
            "policies": "identical",
        },
    )
