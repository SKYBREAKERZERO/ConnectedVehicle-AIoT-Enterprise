"""Serialize transactional PostgreSQL migrations, including caller-owned connections."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext

from sqlalchemy import text
from sqlalchemy.engine import Connection

from enterprise_platform.config.settings import Settings

# Stable database-local bigint key: ASCII CVMIGRAT. Do not change across releases.
MIGRATION_LOCK_KEY = 0x43564D4947524154


@contextmanager
def migration_transaction(connection: Connection, settings: Settings) -> Iterator[None]:
    if connection.dialect.name != "postgresql":
        raise ValueError("Migration guard requires PostgreSQL")
    if connection.get_execution_options().get("isolation_level") == "AUTOCOMMIT":
        raise ValueError("Migration guard requires a transactional connection")
    transaction = nullcontext() if connection.in_transaction() else connection.begin()
    with transaction:
        for name, value in (
            ("application_name", "connected-vehicle-migration"),
            ("lock_timeout", f"{max(1, int(settings.migration_lock_timeout_seconds * 1000))}ms"),
            (
                "statement_timeout",
                f"{max(1, int(settings.migration_statement_timeout_seconds * 1000))}ms",
            ),
        ):
            connection.execute(
                text("SELECT set_config(:name, :value, true)"), {"name": name, "value": value}
            )
        # Acquire before Alembic reads the revision, so a waiter observes the committed head.
        connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        yield
