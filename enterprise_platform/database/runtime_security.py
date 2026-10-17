from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from enterprise_platform.database.credentials import DatabaseRuntime, runtime_database_user
from enterprise_platform.database.ota_authority_contract import FUNCTIONS
from enterprise_platform.database.ota_lifecycle_contract import FUNCTIONS as LIFECYCLE_FUNCTIONS
from enterprise_platform.database.ota_lifecycle_contract import INITIAL_BODY

OTA_TABLES = (
    "ecu_inventory",
    "firmware_releases",
    "ota_jobs",
    "ota_audit_events",
    "ota_executions",
    "ota_execution_reports",
)


async def verify_runtime_database_security(
    engine: AsyncEngine, runtime: DatabaseRuntime, *, tenant_id: str | None = None
) -> None:
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
        if role["username"] != runtime_database_user(runtime, tenant_id) or any(
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
        functions = (
            (
                await connection.execute(
                    text("""
            SELECT p.proname,p.prosrc,p.prosecdef,p.provolatile::text AS provolatile,p.proconfig,
                   pg_get_userbyid(p.proowner) AS owner
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='public' AND p.proname IN
                ('runtime_tenant_binding')
        """)
                )
            )
            .mappings()
            .all()
        )
        expected_functions = {
            "runtime_tenant_binding": (
                "SELECT tenant_id FROM public.runtime_tenant_bindings WHERE role_name=session_user"
            ),
        }
        if len(functions) != 1 or any(
            " ".join(row["prosrc"].split()) != expected_functions.get(row["proname"])
            or not row["prosecdef"]
            or row["provolatile"] != "s"
            or row["proconfig"] != ["search_path=pg_catalog"]
            or row["owner"] == role["username"]
            for row in functions
        ):
            raise RuntimeError("Unsafe runtime policy function contract")
        outbox_function = (
            (
                await connection.execute(
                    text("""
                SELECT p.prosrc,p.prosecdef,p.proisstrict,p.provolatile::text AS volatility
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='public' AND p.proname='outbox_event_tenant'
            """)
                )
            )
            .mappings()
            .all()
        )
        expected_body = (
            "BEGIN RETURN body::jsonb -> 'payload' ->> 'tenant_id'; "
            "EXCEPTION WHEN invalid_text_representation THEN RETURN NULL; END;"
        )
        if len(outbox_function) != 1 or any(
            " ".join(row["prosrc"].split()) != expected_body
            or row["prosecdef"]
            or not row["proisstrict"]
            or row["volatility"] != "i"
            for row in outbox_function
        ):
            raise RuntimeError("Unsafe runtime outbox tenant function contract")
        writable_bindings = await connection.scalar(
            text(
                "SELECT has_table_privilege(current_user,'public.runtime_tenant_bindings',"
                "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')"
            )
        )
        if writable_bindings:
            raise RuntimeError("Unsafe runtime tenant binding privileges")
        binding = await connection.scalar(text("SELECT public.runtime_tenant_binding()"))
        if binding != tenant_id:
            raise RuntimeError("Unsafe runtime tenant binding")
        policies = (
            (
                await connection.execute(
                    text("""
            SELECT c.relname AS table_name,p.polname,p.polpermissive,
                   p.polcmd::text AS polcmd,p.polroles,
                   pg_get_expr(p.polqual,p.polrelid) AS using_expr,
                   pg_get_expr(p.polwithcheck,p.polrelid) AS check_expr
            FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname IN
              ('vehicles','remote_commands','command_reports','telemetry_samples','outbox_events',
               'ecu_inventory','firmware_releases','ota_jobs','ota_audit_events',
               'ota_executions','ota_execution_reports')
        """)
                )
            )
            .mappings()
            .all()
        )
        validate_policy_contract([dict(row) for row in policies])
        protected = await connection.scalar(
            text("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public'
              AND c.relname IN ('vehicles','remote_commands','command_reports',
                                'telemetry_samples','outbox_events','ecu_inventory',
                                'firmware_releases','ota_jobs','ota_audit_events',
                                'ota_executions','ota_execution_reports')
              AND c.relrowsecurity AND pg_get_userbyid(c.relowner) <> current_user
              AND (c.relname NOT IN ('ecu_inventory','firmware_releases','ota_jobs',
                                    'ota_audit_events','ota_executions','ota_execution_reports')
                   OR c.relforcerowsecurity)
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
                          AND p.polname='tenant_guard' AND NOT p.polpermissive)
              AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid
                          AND p.polname='runtime_access')
        """)
        )
        generated_tenant = await connection.scalar(
            text("""
            SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='outbox_events'
              AND a.attname='tenant_id' AND a.attgenerated='s' AND NOT a.attisdropped
              AND pg_get_expr(d.adbin,d.adrelid)='outbox_event_tenant(event_body)'
        """)
        )
        dispatch_order = await connection.scalar(
            text("""SELECT count(*) FROM pg_attribute a
                JOIN pg_class c ON c.oid=a.attrelid
                JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname='remote_commands'
                  AND a.attname='dispatch_order' AND a.attidentity='a' AND NOT a.attisdropped""")
        )
        # Catalogs reveal structure without granting workers access to other runtimes' tables.
        if protected != 11 or generated_tenant != 1 or dispatch_order != 1:
            raise RuntimeError("Unsafe runtime database schema; apply tenant RLS migrations")
        for table in OTA_TABLES:
            privileges = (
                (
                    await connection.execute(
                        text("""
                SELECT has_table_privilege(:table,'SELECT') AS read,
                       has_table_privilege(:table,'INSERT') AS insert,
                       has_table_privilege(:table,'DELETE,TRUNCATE,REFERENCES,TRIGGER') AS excess,
                       has_table_privilege(:table,'UPDATE') AS broad_update,
                       has_any_column_privilege(:table,'UPDATE') AS any_update
            """),
                        {"table": "public." + table},
                    )
                )
                .mappings()
                .one()
            )
            allowed = runtime == "application"
            if dict(privileges) != dict(
                read=allowed,
                insert=allowed and table in {"firmware_releases", "ota_jobs"},
                excess=False,
                broad_update=False,
                any_update=False,
            ):
                raise RuntimeError("Unsafe OTA runtime privilege contract")
        immutable_job_columns = (
            "tenant_id",
            "id",
            "vehicle_id",
            "ecu_id",
            "release_id",
            "ecu_type",
            "hardware_version",
            "idempotency_key",
            "created_at",
            "created_by",
        )
        for column in immutable_job_columns:
            if await connection.scalar(
                text("SELECT has_column_privilege('public.ota_jobs',:column,'UPDATE')"),
                {"column": column},
            ):
                raise RuntimeError("Unsafe OTA immutable job privileges")
        for table, columns in {
            "ecu_inventory": (
                "bootstrap_confirmed",
                "firmware_version",
                "security_version",
                "tenant_id",
                "id",
                "vehicle_id",
                "ecu_type",
                "hardware_version",
                "serial_number",
                "created_at",
                "created_by",
            ),
            "ota_executions": (
                "tenant_id",
                "id",
                "release_id",
                "verification_operation",
                "verification_sha256",
                "manifest",
                "signature",
                "verified_at",
            ),
        }.items():
            for column in columns:
                if await connection.scalar(
                    text("SELECT has_column_privilege(:table,:column,'UPDATE')"),
                    {"table": table, "column": column},
                ):
                    raise RuntimeError("Unsafe OTA execution immutable privileges")
        guards = (
            (
                await connection.execute(
                    text("""SELECT p.prosrc,p.prosecdef,p.proconfig,
            pg_get_userbyid(p.proowner) AS owner,t.tgenabled::text AS tgenabled,
            t.tgtype,t.tgattr::text AS guard_columns,t.tgqual,t.tgconstraint
            FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname='ecu_inventory'
              AND t.tgname='ota_monotonic_version' AND NOT t.tgisinternal""")
                )
            )
            .mappings()
            .all()
        )
        body = (
            "BEGIN IF NEW.security_version < OLD.security_version OR "
            "(NEW.firmware_version IS DISTINCT FROM OLD.firmware_version AND "
            "NEW.security_version <= OLD.security_version) THEN "
            "RAISE EXCEPTION 'OTA security counter cannot regress' USING ERRCODE='23514'; "
            "END IF; RETURN NEW; END;"
        )
        if len(guards) != 1 or any(
            " ".join(row["prosrc"].split()) != body
            or row["prosecdef"]
            or row["proconfig"] != ["search_path=pg_catalog"]
            or row["tgenabled"] != "O"
            or row["tgtype"] != 19
            or row["guard_columns"] != ""
            or row["tgqual"] is not None
            or row["tgconstraint"] != 0
            or row["owner"] == role["username"]
            for row in guards
        ):
            raise RuntimeError("Unsafe OTA monotonic security counter guard")
        for column in ("security_version", "bootstrap_confirmed"):
            if await connection.scalar(
                text("SELECT has_column_privilege('public.ecu_inventory',:column,'INSERT')"),
                {"column": column},
            ):
                raise RuntimeError("Unsafe OTA initial security counter privilege")
        if await connection.scalar(
            text("SELECT has_schema_privilege('ota_authority','USAGE,CREATE')")
        ):
            raise RuntimeError("Unsafe OTA private authority schema access")
        contracts = {
            **FUNCTIONS,
            **{
                name: (arguments, body)
                for name, (arguments, _, body) in LIFECYCLE_FUNCTIONS.items()
            },
        }
        for name, (_, expected_body) in contracts.items():
            rows = (
                (
                    await connection.execute(
                        text("""SELECT p.prosrc,p.prosecdef,p.proconfig,
                pg_get_userbyid(p.proowner) AS owner,
                has_function_privilege(p.oid,'EXECUTE') AS execute,
                EXISTS(SELECT FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                       WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='public' AND p.proname=:name"""),
                        {"name": name},
                    )
                )
                .mappings()
                .all()
            )
            if len(rows) != 1 or any(
                " ".join(row["prosrc"].split()) != " ".join(expected_body.split())
                or not row["prosecdef"]
                or row["proconfig"] != ["search_path=pg_catalog"]
                or row["owner"] != guards[0]["owner"]
                or row["public_execute"]
                or row["execute"] != (runtime == "application" and name != "ota_apply_installation")
                for row in rows
            ):
                raise RuntimeError("Unsafe OTA installation authority function")
        initial = (
            (
                await connection.execute(
                    text("""SELECT p.prosrc,p.prosecdef,p.proconfig,
            pg_get_userbyid(p.proowner) AS owner,t.tgenabled::text AS enabled,t.tgtype
            FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_class c ON c.oid=t.tgrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
            AND c.relname='ota_jobs' AND t.tgname='ota_initial_intent' AND NOT t.tgisinternal""")
                )
            )
            .mappings()
            .all()
        )
        if len(initial) != 1 or any(
            " ".join(row["prosrc"].split()) != " ".join(INITIAL_BODY.split())
            or row["prosecdef"]
            or row["proconfig"] != ["search_path=pg_catalog"]
            or row["owner"] != guards[0]["owner"]
            or row["enabled"] != "O"
            or row["tgtype"] != 7
            for row in initial
        ):
            raise RuntimeError("Unsafe OTA initial intent guard")


def validate_policy_contract(policies: list[dict[str, Any]]) -> None:
    """Exact PostgreSQL deparse contract: fail closed on any policy semantic drift."""
    guard = (
        "((tenant_id)::text = COALESCE(runtime_tenant_binding(), "
        "NULLIF(current_setting('app.tenant_id'::text, true), ''::text)))"
    )
    expected = {
        table: guard
        for table in (
            "vehicles",
            "remote_commands",
            "command_reports",
            "telemetry_samples",
            "outbox_events",
            *OTA_TABLES,
        )
    }
    expected["outbox_events"] = f"((CURRENT_USER = 'outbox_worker'::name) OR {guard})"
    if len(policies) != 22:
        raise RuntimeError("Unsafe runtime policy contract: unexpected policy count")
    seen: set[tuple[str, str]] = set()
    for policy in policies:
        table, name = policy["table_name"], policy["polname"]
        key = (table, name)
        if key in seen or table not in expected or name not in {"runtime_access", "tenant_guard"}:
            raise RuntimeError("Unsafe runtime policy contract: unexpected policy")
        seen.add(key)
        expression = expected[table] if name == "tenant_guard" else "true"
        if (
            policy["polroles"] != [0]
            or policy["polcmd"] != "*"
            or policy["polpermissive"] != (name == "runtime_access")
            or policy["using_expr"] != expression
            or policy["check_expr"] != expression
        ):
            raise RuntimeError("Unsafe runtime policy contract: semantic drift")
