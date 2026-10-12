from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import text

from enterprise_platform.database.engine import create_database_engine
from tests.integration.day12.migration_support import OWNER, Harness, snapshot
from tests.integration.day12.test_migrations import rehearsal, shared_upgrade

__all__ = ["rehearsal"]


@pytest.mark.integration
async def test_shared_connections_reject_superuser_and_set_role(rehearsal: Harness) -> None:
    settings = rehearsal.restore("day12_identity_proxy")
    safe = create_database_engine(settings)
    admin = create_database_engine(
        settings.model_copy(
            update={
                "database_username": "postgres",
                "database_password": SecretStr("test-admin"),
            }
        )
    )
    try:
        before = await snapshot(safe)
        for assumed in (False, True):
            async with admin.connect() as connection:
                if assumed:
                    await connection.execute(text(f"SET ROLE {OWNER}"))
                    await connection.commit()
                with pytest.raises(ValueError, match="Unsafe migration"):
                    await connection.run_sync(shared_upgrade)
            assert await snapshot(safe) == before
    finally:
        await safe.dispose()
        await admin.dispose()


@pytest.mark.integration
@pytest.mark.parametrize(
    "attribute",
    [
        "SUPERUSER",
        "BYPASSRLS",
        "CREATEDB",
        "CREATEROLE",
        "REPLICATION",
        "INHERIT",
    ],
)
async def test_role_attribute_drift_rejected_before_any_ddl(
    rehearsal: Harness, attribute: str
) -> None:
    settings = rehearsal.restore("day12_identity_" + attribute.lower())
    engine = create_database_engine(settings)
    try:
        before = await snapshot(engine)
        rehearsal.sql(settings.database_name, f"ALTER ROLE {OWNER} {attribute}")
        try:
            async with engine.connect() as connection:
                with pytest.raises(ValueError, match="Unsafe migration"):
                    await connection.run_sync(shared_upgrade)
        finally:
            rehearsal.sql(settings.database_name, f"ALTER ROLE {OWNER} NO{attribute}")
        assert await snapshot(engine) == before
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_membership_and_database_owner_drift_rejected(rehearsal: Harness) -> None:
    settings = rehearsal.restore("day12_identity_membership")
    engine = create_database_engine(settings)
    try:
        before = await snapshot(engine)
        rehearsal.sql(settings.database_name, "CREATE ROLE identity_parent NOLOGIN")
        operations: list[tuple[str, str]] = [
            (f"GRANT identity_parent TO {OWNER}", f"REVOKE identity_parent FROM {OWNER}"),
            (
                f"ALTER DATABASE {settings.database_name} OWNER TO postgres",
                f"ALTER DATABASE {settings.database_name} OWNER TO {OWNER}",
            ),
        ]
        for change, undo in operations:
            rehearsal.sql(settings.database_name, change)
            try:
                async with engine.connect() as connection:
                    with pytest.raises(ValueError, match="Unsafe migration"):
                        await connection.run_sync(shared_upgrade)
            finally:
                rehearsal.sql(settings.database_name, undo)
            assert await snapshot(engine) == before
        role: dict[str, Any]
        async with engine.connect() as connection:
            role = dict(
                (
                    await connection.execute(
                        text("""SELECT session_user::text,
                current_user::text,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,
                rolreplication,rolinherit FROM pg_roles WHERE rolname=current_user""")
                    )
                )
                .mappings()
                .one()
            )
        assert role["session_user"] == role["current_user"] == OWNER
        assert not any(
            value for key, value in role.items() if key not in {"session_user", "current_user"}
        )
    finally:
        await engine.dispose()
