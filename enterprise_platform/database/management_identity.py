"""Check the actual database principal before any management action."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

from enterprise_platform.database.credentials import DATABASE_USERS


def verify_migration_identity(connection: Connection, expected: str | None) -> None:
    if (
        not expected
        or expected == "observability_reader"
        or any(
            expected == role or expected.startswith(role + "__") for role in DATABASE_USERS.values()
        )
    ):
        raise ValueError("An independent migration identity is required")
    row = (
        connection.execute(
            text("""SELECT session_user::text AS session_name,
        current_user::text AS current_name,r.rolsuper,r.rolbypassrls,r.rolcreatedb,
        r.rolcreaterole,r.rolreplication,r.rolinherit,r.rolcanlogin,
        pg_get_userbyid(d.datdba) AS database_owner,
        EXISTS (SELECT FROM pg_auth_members m WHERE m.member=r.oid) AS memberships
        FROM pg_roles r JOIN pg_database d ON d.datname=current_database()
        WHERE r.rolname=current_user""")
        )
        .mappings()
        .one()
    )
    if (
        row["session_name"] != expected
        or row["current_name"] != expected
        or row["database_owner"] != expected
        or row["rolcanlogin"] is not True
        or any(
            row[key] is not False
            for key in (
                "rolsuper",
                "rolbypassrls",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolinherit",
                "memberships",
            )
        )
    ):
        raise ValueError("Unsafe migration database identity")


def verify_bootstrap_identity(connection: Connection, expected: str) -> None:
    row = (
        connection.execute(
            text("""SELECT session_user::text AS session_name,
        current_user::text AS current_name,rolsuper,rolcreaterole FROM pg_roles
        WHERE rolname=current_user""")
        )
        .mappings()
        .one()
    )
    if (
        row["session_name"] != expected
        or row["current_name"] != expected
        or not (row["rolsuper"] or row["rolcreaterole"])
    ):
        raise ValueError("Unsafe bootstrap database identity")
