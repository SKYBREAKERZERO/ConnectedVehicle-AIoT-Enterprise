"""Released-code database backups and password-free PostgreSQL catalog evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine
from tests.e2e.test_independent_runtimes import ROOT, docker

DAY11 = "819061de39eb2adb0ce47b61d465cd0f7891a3c1"
LEGACY = "a37e610c952d"
HEAD = "b16f238d45ac"
TABLES = ("vehicles", "remote_commands", "command_reports", "telemetry_samples", "outbox_events")
RUNTIMES = ("app_user", "outbox_worker", "remote_command_worker")
OWNER = "migration_owner"

CATALOG = {
    "tables": """SELECT c.relname,c.relkind::text,pg_get_userbyid(c.relowner) AS owner,
        c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON
        n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S') ORDER BY
        c.relname""",
    "columns": """SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) AS type,
        a.attnotnull,a.attidentity::text,a.attgenerated::text,
        pg_get_expr(d.adbin,d.adrelid) AS default_expression
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE n.nspname='public' AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped
        ORDER BY c.relname,a.attnum""",
    "indexes": """SELECT tablename,indexname,indexdef FROM pg_indexes
        WHERE schemaname='public' ORDER BY indexname""",
    "constraints": """SELECT c.relname,p.conname,p.contype::text,p.convalidated,
        pg_get_constraintdef(p.oid) AS definition FROM pg_constraint p JOIN pg_class c ON
        c.oid=p.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
        ORDER BY c.relname,p.conname""",
    "functions": """SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS arguments,
        pg_get_function_result(p.oid) AS result,l.lanname,p.prosrc,p.prosecdef,
        p.provolatile::text,p.proisstrict,p.proconfig,pg_get_userbyid(p.proowner) AS owner
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON
        l.oid=p.prolang WHERE n.nspname='public' ORDER BY p.proname,arguments""",
    "policies": """SELECT c.relname,p.polname,p.polpermissive,p.polcmd::text,
        ARRAY(SELECT CASE WHEN r=0 THEN 'PUBLIC' ELSE pg_get_userbyid(r) END
              FROM unnest(p.polroles) r ORDER BY r) AS roles,
        pg_get_expr(p.polqual,p.polrelid) AS using_expression,
        pg_get_expr(p.polwithcheck,p.polrelid) AS check_expression
        FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid ORDER BY c.relname,p.polname""",
    "table_grants": """SELECT c.relname,pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN
        'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable FROM pg_class c JOIN pg_namespace n ON
        n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault( CASE
        WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) a WHERE
        n.nspname='public' AND c.relkind IN ('r','p','S') ORDER BY
        c.relname,grantor,grantee,a.privilege_type""",
    "column_grants": """SELECT c.relname,t.attname,pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable FROM pg_attribute t JOIN pg_class c ON c.oid=t.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(t.attacl) a
        WHERE n.nspname='public' ORDER BY c.relname,t.attname,grantor,grantee,a.privilege_type""",
    "function_grants": """SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS arguments,
        pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
        WHERE n.nspname='public' ORDER BY p.proname,arguments,grantor,grantee,a.privilege_type""",
    "schema_grants": """SELECT pg_get_userbyid(n.nspowner) AS owner,
        pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE n.nspname='public' ORDER BY grantor,grantee,a.privilege_type""",
    "database_grants": """SELECT pg_get_userbyid(d.datdba) AS owner,
        pg_get_userbyid(a.grantor) AS grantor,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
        a.privilege_type,a.is_grantable FROM pg_database d
        CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a
        WHERE d.datname=current_database() ORDER BY grantor,grantee,a.privilege_type""",
    "default_grants": """SELECT pg_get_userbyid(d.defaclrole) AS owner,
        COALESCE(n.nspname,'') AS schema,d.defaclobjtype::text,d.defaclacl::text
        FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
        ORDER BY owner,schema,d.defaclobjtype""",
    "roles": """SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,
        rolcanlogin,rolinherit,rolconnlimit,rolvaliduntil,rolconfig FROM pg_roles WHERE
        rolname IN ('migration_owner','app_user','outbox_worker','remote_command_worker')
        ORDER BY rolname""",
    "memberships": """SELECT parent.rolname AS parent,child.rolname AS member,m.admin_option FROM
        pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON
        child.oid=m.member WHERE child.rolname IN
        ('migration_owner','app_user','outbox_worker','remote_command_worker') ORDER BY
        parent,member""",
    "sequences": """SELECT c.relname,s.seqstart,s.seqincrement,s.seqmax,
        s.seqmin,s.seqcache,s.seqcycle
        FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON
        n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname""",
}


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()


def sha(value: object) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def normalized_constraint(definition: str) -> str:
    # pg_restore reparses varchar enum arrays as element-wise text casts.
    # Normalize only these equivalent literal casts; all predicates remain intact.
    literal = r"'(?:[^']|'')*'"
    outer = re.fullmatch(
        r"CHECK \(\(\((status|command_type)\)::text = ANY \((.+)\)\)\)", definition
    )
    element = rf"(?:{literal}::(?:character varying|text)|\({literal}::character varying\)::text)"
    elements = rf"{element}(?:, {element})*"
    if (
        outer is None
        or re.fullmatch(
            rf"(?:\(ARRAY\[{elements}\]\)::text\[\]|ARRAY\[{elements}\])", outer.group(2)
        )
        is None
    ):
        return definition
    definition = re.sub(r"\((" + literal + r")::character varying\)::text", r"\1::text", definition)
    definition = re.sub(r"(" + literal + r")::character varying", r"\1::text", definition)
    return re.sub(r"\(\(ARRAY\[([^\]]+)\]\)::text\[\]\)", r"(ARRAY[\1])", definition)


async def snapshot(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as connection:
        catalog = {
            name: [dict(row) for row in (await connection.execute(text(sql))).mappings()]
            for name, sql in CATALOG.items()
        }
        raw_constraints = [dict(row) for row in catalog["constraints"]]
        for row in catalog["constraints"]:
            row["definition"] = normalized_constraint(row["definition"])
        data = {}
        for table in TABLES:
            rows: Sequence[str] = (
                (
                    await connection.execute(
                        text(f"SELECT to_jsonb(t)::text FROM {table} t ORDER BY 1")
                    )
                )
                .scalars()
                .all()
            )
            data[table] = {"rows": len(rows), "sha256": sha(rows)}
            data[table]["tenant_row_counts"] = list(
                (
                    await connection.execute(
                        text(f"SELECT count(*) FROM {table} GROUP BY tenant_id ORDER BY count(*)")
                    )
                ).scalars()
            )
        relationships = {}
        for name, sql in {
            "command_vehicle": """SELECT count(*) FROM remote_commands c
                JOIN vehicles v ON v.id=c.vehicle_id
                WHERE c.tenant_id<>v.tenant_id""",
            "report_command_vehicle": """SELECT count(*) FROM command_reports r
                JOIN remote_commands c ON c.id=r.command_id
                WHERE r.tenant_id<>c.tenant_id OR r.vehicle_id<>c.vehicle_id""",
            "telemetry_vehicle": """SELECT count(*) FROM telemetry_samples t
                JOIN vehicles v ON v.id=t.vehicle_id
                WHERE t.tenant_id<>v.tenant_id""",
            "outbox_command": """SELECT count(*) FROM outbox_events o LEFT JOIN remote_commands c
                ON c.id=o.event_body::jsonb->'payload'->>'command_id'
                WHERE c.id IS NULL OR o.tenant_id<>c.tenant_id
                OR o.event_body::jsonb->'payload'->>'vehicle_id'<>c.vehicle_id""",
        }.items():
            relationships[name] = await connection.scalar(text(sql))
        sequences = {}
        for row in catalog["sequences"]:
            sequences[row["relname"]] = dict(
                (
                    await connection.execute(
                        text(f"SELECT last_value,is_called FROM {row['relname']}")
                    )
                )
                .mappings()
                .one()
            )
        revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    return {
        "revision": revision,
        "catalog": catalog,
        "catalog_sha256": sha(catalog),
        "data": data,
        "sequence_state": sequences,
        "raw_constraints": raw_constraints,
        "relationships": relationships,
    }


def catalog_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for section, old in before["catalog"].items():
        previous = {encoded(row).decode() for row in old}
        current = {encoded(row).decode() for row in after["catalog"][section]}
        if previous != current:
            result[section] = {
                "removed": [json.loads(row) for row in sorted(previous - current)],
                "added": [json.loads(row) for row in sorted(current - previous)],
            }
    return result


def environment(settings: Settings) -> dict[str, str]:
    env = dict(
        os.environ,
        DATABASE_HOST=settings.database_host,
        DATABASE_PORT=str(settings.database_port),
        DATABASE_NAME=settings.database_name,
        MIGRATION_DATABASE_USERNAME=OWNER,
        MIGRATION_DATABASE_PASSWORD="test-migration",
        DATABASE_PASSWORD="test-migration",
        MIGRATION_LOCK_TIMEOUT_SECONDS=str(settings.migration_lock_timeout_seconds),
        MIGRATION_STATEMENT_TIMEOUT_SECONDS=str(settings.migration_statement_timeout_seconds),
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
    )
    env.pop("DATABASE_TENANT_ID", None)
    return env


@dataclass
class Harness:
    container: str
    port: int
    release: Path
    backup: Path
    backup_sha256: str = ""
    source_snapshot: dict[str, Any] | None = None

    def sql(self, database: str, sql: str, *, user: str = "postgres") -> str:
        return docker(
            "exec",
            self.container,
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            user,
            "-d",
            database,
            "-At",
            "-c",
            sql,
        )

    def database(self, name: str) -> Settings:
        self.sql("postgres", f"CREATE DATABASE {name} OWNER {OWNER}")
        self.sql(
            name,
            f"REVOKE ALL ON DATABASE {name} FROM PUBLIC; GRANT CONNECT ON DATABASE {name} "
            f"TO {OWNER},app_user,outbox_worker,remote_command_worker",
        )
        return Settings.model_construct(
            database_host="127.0.0.1",
            database_port=self.port,
            database_name=name,
            database_username=OWNER,
            database_password=SecretStr("test-migration"),
            migration_database_username=OWNER,
            migration_database_password=SecretStr("test-migration"),
        )

    def upgrade(
        self, settings: Settings, *, release: bool = False, expected: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=self.release if release else ROOT,
            env=environment(settings),
            capture_output=True,
            timeout=90,
        )
        if expected and result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        return result

    def grants(self, settings: Settings, *, release: bool = False) -> None:
        source = (self.release if release else ROOT) / "database/runtime-grants.sql"
        self.sql(settings.database_name, source.read_text(encoding="utf-8"))

    def dump(self, settings: Settings) -> None:
        data = subprocess.check_output(
            [
                "docker",
                "exec",
                self.container,
                "pg_dump",
                "-U",
                OWNER,
                "-d",
                settings.database_name,
                "--format=custom",
            ]
        )
        self.backup.write_bytes(data)
        self.backup_sha256 = hashlib.sha256(data).hexdigest()

    def restore(self, name: str, *, preserve_acl: bool = True) -> Settings:
        settings = self.database(name)
        data = self.backup.read_bytes()
        if hashlib.sha256(data).hexdigest() != self.backup_sha256:
            raise ValueError("Day11 backup digest mismatch")
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                self.container,
                "pg_restore",
                "-U",
                OWNER,
                "-d",
                name,
                "--exit-on-error",
                "--no-owner",
                *([] if preserve_acl else ["--no-acl"]),
            ],
            input=data,
            capture_output=True,
        )
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        return settings


def released_checkout(directory: Path) -> None:
    archive = directory / "day11-source.tar"
    archive.write_bytes(subprocess.check_output(["git", "archive", DAY11], cwd=ROOT))
    release = directory / "release"
    release.mkdir()
    with tarfile.open(archive) as stream:
        stream.extractall(release, filter="data")


def start_harness(directory: Path) -> Harness:
    released_checkout(directory)
    name = "vehicle-migration-rehearsal-" + uuid4().hex[:10]
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::5432",
        "-e",
        "POSTGRES_PASSWORD=test-admin",
        "postgres:16-alpine",
    )
    try:
        port = int(docker("port", name, "5432").split(":")[-1])
        harness = Harness(name, port, directory / "release", directory / "day11.dump")
        deadline = time.monotonic() + 30
        while subprocess.run(
            ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
            capture_output=True,
        ).returncode:
            if time.monotonic() > deadline:
                raise TimeoutError("Migration PostgreSQL did not start")
            time.sleep(0.2)
        for role in (OWNER, *RUNTIMES):
            password = "test-migration" if role == OWNER else f"test-{role}"
            harness.sql(
                "postgres",
                f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB "
                f"NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD '{password}'",
            )
        return harness
    except BaseException:
        docker("rm", "-f", name)
        raise


async def seed(connection: AsyncConnection) -> None:
    for tenant in ("history-a", "history-b"):
        for index in range(3):
            vehicle = str(uuid4())
            await connection.execute(
                text("""INSERT INTO vehicles
                VALUES (:id,:vin,:tenant,'active','2026-10-01','2026-10-01')"""),
                {
                    "id": vehicle,
                    "vin": ("A" if tenant.endswith("a") else "B") + f"{index:016d}",
                    "tenant": tenant,
                },
            )
            for sample in range(2):
                await connection.execute(
                    text("""INSERT INTO telemetry_samples VALUES
                    (:id,:tenant,:vehicle,'2026-10-01','2026-10-01',:sample)"""),
                    {
                        "id": str(uuid4()),
                        "tenant": tenant,
                        "vehicle": vehicle,
                        "sample": json.dumps(
                            {"speed_kph": sample * 10, "battery_percent": 80, "temperature_c": 20}
                        ),
                    },
                )
            for order, status in enumerate(("requested", "succeeded", "failed")):
                command = str(uuid4())
                await connection.execute(
                    text("""INSERT INTO remote_commands
        (id,vehicle_id,tenant_id,command_type,status,idempotency_key,created_at,updated_at,expires_at)
        VALUES
        (:id,:vehicle,:tenant,'lock',:status,:key,'2026-10-01','2026-10-01','2026-10-02')"""),
                    {
                        "id": command,
                        "vehicle": vehicle,
                        "tenant": tenant,
                        "status": status,
                        "key": f"history-{order}",
                    },
                )
                for report_status in (
                    "acknowledged",
                    "failed" if status == "failed" else "succeeded",
                ):
                    await connection.execute(
                        text("""INSERT INTO command_reports VALUES
                        (:event,:command,:tenant,:vehicle,:report,'2026-10-01')"""),
                        {
                            "event": str(uuid4()),
                            "command": command,
                            "tenant": tenant,
                            "vehicle": vehicle,
                            "report": json.dumps(
                                {
                                    "status": report_status,
                                    "failure_code": "ECU_FAILURE"
                                    if report_status == "failed"
                                    else None,
                                }
                            ),
                        },
                    )
                event = str(uuid4())
                await connection.execute(
                    text("""INSERT INTO outbox_events
        (id,event_id,event_type,destination,event_body,status,attempts,created_at,available_at)
        VALUES (:id,:id,'remote_command.requested','vehicle-command',:body,:status,:attempts,
        '2026-10-01','2026-10-01')"""),
                    {
                        "id": event,
                        "body": json.dumps(
                            {
                                "payload": {
                                    "tenant_id": tenant,
                                    "vehicle_id": vehicle,
                                    "command_id": command,
                                    "command_type": "lock",
                                }
                            }
                        ),
                        "status": ("pending", "published", "failed")[order],
                        "attempts": order,
                    },
                )


def runtime_engine(settings: Settings, user: str = "app_user") -> AsyncEngine:
    return create_database_engine(
        settings.model_copy(
            update={
                "database_username": user,
                "database_password": SecretStr(f"test-{user}"),
            }
        )
    )
