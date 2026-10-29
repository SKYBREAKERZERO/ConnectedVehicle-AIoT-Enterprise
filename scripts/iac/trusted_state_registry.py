"""Day29 local authenticated-publisher registry; no AWS or production authority.

Bootstrap policy, identity adapter, filesystem and SQLite host are trusted inputs.
Record hashes detect inconsistent data, not an administrator rewriting the DB.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.iac.plan_admission import canonical_digest
from scripts.iac.state_integrity import state_errors, validate_record

Authenticator = Callable[[str, str, str], bool]
Clock = Callable[[], datetime]
BACKEND_FIELDS = {"account", "environment", "bucket", "key"}


def identity(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", value) is None:
        raise ValueError("valid authenticated principal required")
    return value.casefold()


def identifier(value: str) -> str:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is None:
        raise ValueError("bounded identifier required")
    return value


def utc(clock: Clock) -> datetime:
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("trusted UTC clock required")
    return now


def backend(value: dict[str, Any]) -> dict[str, str]:
    if set(value) != BACKEND_FIELDS or any(type(v) is not str for v in value.values()):
        raise ValueError("closed backend scope required")
    validate_record(
        {
            **value,
            "version_id": "scope",
            "sha256": "0" * 64,
            "lineage": "11111111-1111-1111-1111-111111111111",
            "serial": 0,
            "commit": "0" * 40,
            "run_id": "1:1",
        }
    )
    return dict(value)


@contextmanager
def governance_db(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path, timeout=2)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        yield connection
    finally:
        connection.close()


def authenticated(adapter: Authenticator, actor: str, action: str, digest: str) -> None:
    try:
        if adapter(actor, action, digest) is not True:
            raise ValueError("identity authority denied")
    except Exception as exc:
        raise ValueError("identity authority unavailable or denied") from exc


class TrustedStateRegistry:
    """Immutable versions, monotonic head and explicit revocation in a local DB.

    Methods authenticate mutations against constructor-owned policy. Lookups never
    accept a caller-supplied trust callback; only the exact active head verifies.
    """

    def __init__(
        self,
        path: Path,
        *,
        scope: dict[str, Any],
        registrars: frozenset[str],
        authenticate: Authenticator,
    ):
        self.path = path.resolve()
        self._scope_json = json.dumps(backend(deepcopy(scope)), sort_keys=True)
        self.scope_id = canonical_digest(json.loads(self._scope_json))
        self._registrars = frozenset(identity(p) for p in registrars)
        if not self._registrars:
            raise ValueError("explicit registrars required")
        self._authenticate = authenticate
        config = canonical_digest({"scope": self.scope, "registrars": sorted(self._registrars)})
        with governance_db(self.path) as connection:
            tables = {
                r[0]
                for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            release_tables = {"releases", "spent", "holders", "events"}
            existing_release = {
                t for t in tables if not t.startswith("day29_") and t != "sqlite_sequence"
            }
            if existing_release and existing_release != release_tables:
                raise ValueError("use a dedicated IaC governance database, not a business DB")
            if existing_release:
                columns = {
                    "releases": ["id", "binding", "state", "approval", "actor"],
                    "spent": ["plan_id", "request_id"],
                    "holders": ["backend", "request_id"],
                    "events": ["sequence", "request_id", "state", "detail"],
                }
                for table, wanted in columns.items():
                    # Table names come only from the fixed internal allowlist.
                    if [r[1] for r in connection.execute(f"PRAGMA table_info({table})")] != wanted:
                        raise ValueError("unexpected existing Day27 governance schema")
            if tables:
                if "day29_meta" not in tables:
                    raise ValueError(
                        "uninitialized/legacy database needs explicit governance migration"
                    )
                purpose_row = connection.execute(
                    "SELECT value FROM day29_meta WHERE name='purpose'"
                ).fetchone()
                if purpose_row is None or purpose_row[0] != "iac-governance-offline-v1":
                    raise ValueError("existing governance data lacks a trusted purpose marker")
            if any(
                not t.startswith("day29_")
                and t not in {"releases", "spent", "holders", "events", "sqlite_sequence"}
                for t in tables
            ):
                raise ValueError("use a dedicated IaC governance database, not a business DB")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS day29_meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS day29_versions (
                    backend TEXT NOT NULL, version_id TEXT NOT NULL, record TEXT NOT NULL,
                    digest TEXT NOT NULL, registrar TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','SUPERSEDED','REVOKED')),
                    PRIMARY KEY(backend,version_id)
                );
                CREATE TABLE IF NOT EXISTS day29_heads (
                    backend TEXT PRIMARY KEY, version_id TEXT NOT NULL,
                    lineage TEXT NOT NULL, serial INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS day29_audit (
                    sequence INTEGER PRIMARY KEY, subject TEXT NOT NULL,
                    action TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            purpose = connection.execute(
                "SELECT value FROM day29_meta WHERE name='purpose'"
            ).fetchone()
            if purpose is not None and purpose[0] != "iac-governance-offline-v1":
                raise ValueError("unexpected governance database purpose")
            connection.execute(
                "INSERT OR IGNORE INTO day29_meta VALUES ('purpose','iac-governance-offline-v1')"
            )
            name = "registry:" + self.scope_id
            previous = connection.execute(
                "SELECT value FROM day29_meta WHERE name=?", (name,)
            ).fetchone()
            if previous is not None and previous[0] != config:
                raise ValueError("registry bootstrap policy changed; explicit migration required")
            connection.execute("INSERT OR IGNORE INTO day29_meta VALUES (?,?)", (name, config))
            connection.commit()

    @property
    def scope(self) -> dict[str, str]:
        return dict(json.loads(self._scope_json))

    def _check_scope(self, record: dict[str, Any]) -> None:
        validate_record(record)
        if {k: record[k] for k in BACKEND_FIELDS} != self.scope:
            raise ValueError("state belongs to another account/environment/backend")

    def register(self, raw: bytes, record: dict[str, Any], *, actor: str) -> None:
        record = deepcopy(record)
        self._check_scope(record)
        actor = identity(actor)
        if actor not in self._registrars:
            raise ValueError("publisher not authorized")
        authenticated(self._authenticate, actor, "register-state", canonical_digest(record))
        # Authentication/authorization already succeeded above. Here Day28 is
        # reused only for byte/schema consistency of a not-yet-registered record.
        errors = state_errors(raw, observed=record, expected=record, authenticate=lambda _: True)
        if errors:
            raise ValueError("; ".join(errors))
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            head = connection.execute(
                "SELECT version_id,lineage,serial FROM day29_heads WHERE backend=?",
                (self.scope_id,),
            ).fetchone()
            if head is not None and (record["lineage"] != head[1] or record["serial"] <= head[2]):
                raise ValueError("lineage change or stale/nonmonotonic serial denied")
            if connection.execute(
                "SELECT 1 FROM day29_versions WHERE backend=? AND version_id=?",
                (self.scope_id, record["version_id"]),
            ).fetchone():
                raise ValueError("object version is immutable and already registered")
            connection.execute(
                "UPDATE day29_versions SET status='SUPERSEDED' WHERE backend=? AND status='ACTIVE'",
                (self.scope_id,),
            )
            connection.execute(
                "INSERT INTO day29_versions VALUES (?,?,?,?,?,'ACTIVE')",
                (
                    self.scope_id,
                    record["version_id"],
                    json.dumps(record, sort_keys=True),
                    canonical_digest(record),
                    actor,
                ),
            )
            connection.execute(
                "INSERT INTO day29_heads VALUES (?,?,?,?) ON CONFLICT(backend) DO UPDATE "
                "SET version_id=excluded.version_id,lineage=excluded.lineage,"
                "serial=excluded.serial",
                (self.scope_id, record["version_id"], record["lineage"], record["serial"]),
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) VALUES (?,'REGISTER',?,?)",
                (self.scope_id, actor, canonical_digest(record)),
            )
            connection.commit()

    def is_current(self, record: dict[str, Any]) -> bool:
        try:
            self._check_scope(record)
            with governance_db(self.path) as connection:
                row = connection.execute(
                    "SELECT v.record,v.digest,v.status,h.version_id,h.lineage,h.serial,v.registrar "
                    "FROM day29_versions v JOIN day29_heads h ON h.backend=v.backend "
                    "WHERE v.backend=? AND v.version_id=?",
                    (self.scope_id, record["version_id"]),
                ).fetchone()
                return (
                    row is not None
                    and row[2] == "ACTIVE"
                    and row[3] == record["version_id"]
                    and row[4] == record["lineage"]
                    and type(record["serial"]) is int
                    and row[5] == record["serial"]
                    and row[6] in self._registrars
                    and canonical_digest(json.loads(row[0])) == row[1] == canonical_digest(record)
                )
        except Exception:
            return False

    def verify(self, raw: bytes | None, record: dict[str, Any]) -> None:
        record = deepcopy(record)
        errors = state_errors(raw, observed=record, expected=record, authenticate=self.is_current)
        if errors:
            raise ValueError("; ".join(errors))

    def revoke(self, record: dict[str, Any], *, actor: str) -> None:
        record = deepcopy(record)
        self._check_scope(record)
        actor = identity(actor)
        if actor not in self._registrars:
            raise ValueError("revocation actor not authorized")
        authenticated(self._authenticate, actor, "revoke-state", canonical_digest(record))
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT digest FROM day29_versions WHERE backend=? AND version_id=?",
                (self.scope_id, record["version_id"]),
            ).fetchone()
            if row is None or row[0] != canonical_digest(record):
                raise ValueError("unregistered or substituted version")
            connection.execute(
                "UPDATE day29_versions SET status='REVOKED' WHERE backend=? AND version_id=?",
                (self.scope_id, record["version_id"]),
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) "
                "VALUES (?,'REVOKE_STATE',?,?)",
                (self.scope_id, actor, canonical_digest(record)),
            )
            # Head/high-water mark remains, so revocation never falls back to an old version.
            connection.commit()
