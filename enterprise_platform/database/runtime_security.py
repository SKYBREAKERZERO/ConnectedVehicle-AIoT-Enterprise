from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.database.credentials import DATABASE_USERS, DatabaseRuntime


async def verify_runtime_database_security(engine: AsyncEngine, runtime: DatabaseRuntime) -> None:
    """Refuse serving traffic against privileged roles or an unmigrated database."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text("""
            SELECT current_user AS username, rolsuper, rolbypassrls, rolcreatedb,
                   rolcreaterole, rolreplication,
                   has_schema_privilege('public', 'CREATE') AS schema_create,
                   has_database_privilege(current_database(), 'CREATE') AS database_create,
                   has_database_privilege(current_database(), 'TEMP') AS database_temp,
                   EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid) AS membership
            FROM pg_roles r WHERE rolname = current_user
        """)
        )
        role = result.mappings().one()
        if role["username"] != DATABASE_USERS[runtime] or any(
            role[key]
            for key in (
                "rolsuper",
                "rolbypassrls",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "schema_create",
                "database_create",
                "database_temp",
                "membership",
            )
        ):
            raise RuntimeError("Unsafe runtime database role; provision independent runtime grants")
        protected = await connection.scalar(
            text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public'
              AND c.relname IN ('vehicles','remote_commands','command_reports',
                                'telemetry_samples','outbox_events')
              AND c.relrowsecurity AND pg_get_userbyid(c.relowner) <> current_user
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
                          AND p.polname='tenant_guard' AND NOT p.polpermissive)
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
                          AND p.polname='runtime_access')
        """)
        )
        generated_tenant = await connection.scalar(
            text("""
            SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='outbox_events'
              AND a.attname='tenant_id' AND a.attgenerated='s' AND NOT a.attisdropped
        """)
        )
        # Catalogs reveal structure without granting workers access to other runtimes' tables.
        if protected != 5 or generated_tenant != 1:
            raise RuntimeError("Unsafe runtime database schema; apply tenant RLS migrations")
