"""Crash-aware SQLite command journal and durable HTTP report outbox.

This component stores *validated* command envelopes. A MQTT ingress adapter must
validate the existing DispatchPayload contract and authenticate its own device
binding before constructing DeviceCommand. SQLite and an external ECU cannot be
updated atomically: a crash during execution yields UNCERTAIN, never a replay.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4


class DeviceCommandConflictError(ValueError):
    """A command ID was reused with different content or outside device scope."""


class DeviceStoreIdentityError(RuntimeError):
    """The SQLite file is not bound to the configured tenant and vehicle."""


class DeviceCommandExpiredError(ValueError):
    """A new command has expired before being persisted."""


class DeviceExecutionStateError(ValueError):
    """An invalid execution-state transition was attempted."""


class ExecutionState(StrEnum):
    RECEIVED = "received"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    UNCERTAIN = "uncertain"


class DeliveryState(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    DELIVERED = "delivered"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeviceCommand:
    """Values are copied from an already-validated DispatchPayload."""

    command_id: str
    tenant_id: str
    vehicle_id: str
    command_type: str
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for attr in ("command_id", "vehicle_id"):
            value = getattr(self, attr)
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError(f"{attr} must be a canonical UUID string")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.tenant_id):
            raise ValueError("Invalid tenant ID")
        if self.command_type not in {
            "lock",
            "unlock",
            "start",
            "stop",
            "honk",
            "flash_lights",
        }:
            raise ValueError("Unsupported command type")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Command timestamps must be timezone-aware")
        if self.expires_at <= self.created_at or self.expires_at - self.created_at > timedelta(
            seconds=300
        ):
            raise ValueError("Command TTL must be within (0, 300] seconds")

    def digest(self) -> str:
        canonical = {
            "command_id": self.command_id,
            "tenant_id": self.tenant_id,
            "vehicle_id": self.vehicle_id,
            "command_type": self.command_type,
            "created_at": _timestamp(self.created_at),
            "expires_at": _timestamp(self.expires_at),
        }
        return sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredCommand:
    command_id: str
    state: ExecutionState
    command_type: str
    expires_at: datetime
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class LeasedReport:
    event_id: str
    command_id: str
    vehicle_id: str
    status: str
    payload: dict[str, object]
    lease_token: str
    attempt: int


@dataclass(frozen=True, slots=True)
class Reception:
    inserted: bool
    command_id: str


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _now(value: datetime | None) -> datetime:
    stamp = value if value is not None else datetime.now(UTC)
    if stamp.tzinfo is None:
        raise ValueError("Clock must be timezone-aware")
    return stamp.astimezone(UTC)


class DeviceExecutionStore:
    """SQLite, one short IMMEDIATE transaction per change; one file per device.

    Connections are opened per call. The device process must use a local filesystem
    with reliable SQLite locking; do not put this database on a shared NFS volume.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        tenant_id: str,
        vehicle_id: str,
    ) -> None:
        # The identity MUST originate from trusted provisioning, never from
        # a stored command or the MQTT payload. It is immutable for this store.
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", tenant_id):
            raise ValueError("Invalid provisioned tenant ID")
        try:
            if str(UUID(vehicle_id)) != vehicle_id:
                raise ValueError("Vehicle ID must be a canonical UUID")
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("Invalid provisioned vehicle ID") from exc
        self.tenant_id = tenant_id
        self.vehicle_id = vehicle_id
        self.path = Path(database_path)
        if str(self.path) == ":memory:":
            raise ValueError("Use a durable SQLite file, not :memory:")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect(verify_binding=False) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS device_identity (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    tenant_id TEXT NOT NULL,
                    vehicle_id TEXT NOT NULL,
                    bound_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_commands (
                    command_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    vehicle_id TEXT NOT NULL,
                    command_type TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    execution_state TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    failure_code TEXT,
                    CHECK (execution_state IN
                        ('received', 'executing', 'succeeded', 'failed', 'expired', 'uncertain'))
                );
                CREATE TABLE IF NOT EXISTS device_report_outbox (
                    event_id TEXT PRIMARY KEY,
                    command_id TEXT NOT NULL REFERENCES device_commands(command_id),
                    report_status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    delivery_state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL,
                    lease_token TEXT,
                    lease_until TEXT,
                    last_error_code TEXT,
                    created_at TEXT NOT NULL,
                    CHECK (report_status IN ('acknowledged', 'succeeded', 'failed')),
                    CHECK (delivery_state IN ('pending', 'leased', 'delivered', 'blocked')),
                    CHECK (attempts >= 0)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_device_command_ack
                    ON device_report_outbox (command_id)
                    WHERE report_status = 'acknowledged';
                CREATE UNIQUE INDEX IF NOT EXISTS uq_device_command_result
                    ON device_report_outbox (command_id)
                    WHERE report_status IN ('succeeded', 'failed');
                CREATE INDEX IF NOT EXISTS idx_device_reports_due
                    ON device_report_outbox(delivery_state, next_attempt_at);
                CREATE TRIGGER IF NOT EXISTS device_command_scope_insert
                    BEFORE INSERT ON device_commands
                    WHEN NEW.tenant_id !=
                        (SELECT tenant_id FROM device_identity WHERE singleton=1)
                      OR NEW.vehicle_id !=
                        (SELECT vehicle_id FROM device_identity WHERE singleton=1)
                    BEGIN SELECT RAISE(ABORT, 'device identity violation'); END;
                CREATE TRIGGER IF NOT EXISTS device_command_scope_update
                    BEFORE UPDATE OF tenant_id, vehicle_id ON device_commands
                    WHEN NEW.tenant_id !=
                        (SELECT tenant_id FROM device_identity WHERE singleton=1)
                      OR NEW.vehicle_id !=
                        (SELECT vehicle_id FROM device_identity WHERE singleton=1)
                    BEGIN SELECT RAISE(ABORT, 'device identity violation'); END;
                CREATE TRIGGER IF NOT EXISTS device_identity_immutable_update
                    BEFORE UPDATE ON device_identity
                    BEGIN SELECT RAISE(ABORT, 'device identity immutable'); END;
                CREATE TRIGGER IF NOT EXISTS device_identity_immutable_delete
                    BEFORE DELETE ON device_identity
                    BEGIN SELECT RAISE(ABORT, 'device identity immutable'); END;
                """
            )
            # Enroll only a pristine database. An existing legacy SQLite file
            # containing ANY command or report must be quarantined and handled
            # by an explicit, reviewed migration; never silently rebind it.
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT tenant_id, vehicle_id FROM device_identity WHERE singleton=1"
                ).fetchone()
                if row is None:
                    has_work = connection.execute(
                        "SELECT EXISTS(SELECT 1 FROM device_commands) "
                        "OR EXISTS(SELECT 1 FROM device_report_outbox)"
                    ).fetchone()[0]
                    if has_work:
                        raise DeviceStoreIdentityError(
                            "Unbound legacy SQLite contains commands or reports; "
                            "quarantine and migrate explicitly"
                        )
                    connection.execute(
                        "INSERT INTO device_identity "
                        "(singleton, tenant_id, vehicle_id, bound_at) "
                        "VALUES (1, ?, ?, ?)",
                        (self.tenant_id, self.vehicle_id, _timestamp(_now(None))),
                    )
                else:
                    self._assert_identity(connection)
                # Reject any pre-existing mixed-identity rows, including those
                # manually injected into a previously bound SQLite file.
                foreign = connection.execute(
                    "SELECT EXISTS(SELECT 1 FROM device_commands "
                    "WHERE tenant_id<>? OR vehicle_id<>?)",
                    (self.tenant_id, self.vehicle_id),
                ).fetchone()[0]
                if foreign:
                    raise DeviceStoreIdentityError(
                        "Database contains commands for a different device"
                    )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _assert_identity(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT tenant_id, vehicle_id FROM device_identity WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise DeviceStoreIdentityError("Device SQLite identity missing; fail closed")
        if row["tenant_id"] != self.tenant_id or row["vehicle_id"] != self.vehicle_id:
            raise DeviceStoreIdentityError(
                "SQLite belongs to a different tenant/vehicle; refusing recovery"
            )

    @contextmanager
    def _connect(self, *, verify_binding: bool = True) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            if verify_binding:
                self._assert_identity(connection)
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _insert_report(
        connection: sqlite3.Connection,
        *,
        command_id: str,
        status: str,
        now: datetime,
        failure_code: str | None = None,
    ) -> str:
        event_id = str(uuid4())
        report: dict[str, object] = {
            "schema_version": "1.0",
            "event_id": event_id,
            "status": status,
            "occurred_at": _timestamp(now),
        }
        if failure_code is not None:
            report["failure_code"] = failure_code
        stamp = _timestamp(now)
        connection.execute(
            """INSERT INTO device_report_outbox
            (event_id, command_id, report_status, payload_json, delivery_state,
             attempts, next_attempt_at, created_at)
            VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)""",
            (event_id, command_id, status, json.dumps(report, sort_keys=True), stamp, stamp),
        )
        return event_id

    def receive(
        self,
        command: DeviceCommand,
        *,
        trusted_tenant_id: str,
        trusted_vehicle_id: str,
        now: datetime | None = None,
    ) -> Reception:
        if trusted_tenant_id != self.tenant_id or trusted_vehicle_id != self.vehicle_id:
            raise DeviceStoreIdentityError(
                "Caller provisioned identity differs from SQLite device binding"
            )
        if command.tenant_id != self.tenant_id or command.vehicle_id != self.vehicle_id:
            raise DeviceCommandConflictError("Command is not addressed to this device")
        stamp = _now(now)
        digest = command.digest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_hash FROM device_commands WHERE command_id=?",
                (command.command_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != digest:
                    raise DeviceCommandConflictError("Command ID reused with different contents")
                return Reception(inserted=False, command_id=command.command_id)
            if command.expires_at <= stamp:
                raise DeviceCommandExpiredError("Received an already-expired command")
            if command.created_at > stamp + timedelta(minutes=5):
                raise ValueError("Command creation time is unreasonably far in the future")
            connection.execute(
                """INSERT INTO device_commands
                (command_id, tenant_id, vehicle_id, command_type, payload_hash,
                 execution_state, received_at, expires_at)
                VALUES (?, ?, ?, ?, ?, 'received', ?, ?)""",
                (
                    command.command_id,
                    command.tenant_id,
                    command.vehicle_id,
                    command.command_type,
                    digest,
                    _timestamp(stamp),
                    _timestamp(command.expires_at),
                ),
            )
            self._insert_report(
                connection,
                command_id=command.command_id,
                status="acknowledged",
                now=stamp,
            )
            connection.commit()
        return Reception(inserted=True, command_id=command.command_id)

    def get_command(self, command_id: str) -> StoredCommand | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT command_id, command_type, execution_state, expires_at,
                          failure_code FROM device_commands WHERE command_id=?""",
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        return StoredCommand(
            command_id=row["command_id"],
            command_type=row["command_type"],
            state=ExecutionState(row["execution_state"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            failure_code=row["failure_code"],
        )

    def lease_reports(
        self,
        *,
        limit: int = 10,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> list[LeasedReport]:
        if not 1 <= limit <= 100 or not 1 <= lease_seconds <= 300:
            raise ValueError("Invalid report lease parameters")
        stamp = _now(now)
        leased: list[LeasedReport] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT r.event_id, r.command_id, r.report_status, r.payload_json,
                          r.attempts, c.vehicle_id
                   FROM device_report_outbox AS r
                   JOIN device_commands AS c ON c.command_id = r.command_id
                   WHERE ((r.delivery_state='pending' AND r.next_attempt_at <= ?)
                      OR (r.delivery_state='leased' AND r.lease_until <= ?))
                     AND (r.report_status='acknowledged' OR EXISTS (
                         SELECT 1 FROM device_report_outbox AS ack
                         WHERE ack.command_id=r.command_id
                           AND ack.report_status='acknowledged'
                           AND ack.delivery_state='delivered'
                     ))
                   ORDER BY r.created_at, r.event_id LIMIT ?""",
                (_timestamp(stamp), _timestamp(stamp), limit),
            ).fetchall()
            for row in rows:
                token = str(uuid4())
                connection.execute(
                    """UPDATE device_report_outbox
                       SET delivery_state='leased', attempts=attempts+1,
                           lease_token=?, lease_until=?
                       WHERE event_id=?""",
                    (
                        token,
                        _timestamp(stamp + timedelta(seconds=lease_seconds)),
                        row["event_id"],
                    ),
                )
                leased.append(
                    LeasedReport(
                        event_id=row["event_id"],
                        command_id=row["command_id"],
                        vehicle_id=row["vehicle_id"],
                        status=row["report_status"],
                        payload=json.loads(row["payload_json"]),
                        lease_token=token,
                        attempt=int(row["attempts"]) + 1,
                    )
                )
            connection.commit()
        return leased

    def mark_delivered(self, report: LeasedReport) -> bool:
        return self._complete_lease(report, "delivered", None, None)

    def defer(
        self,
        report: LeasedReport,
        *,
        retry_after_seconds: int,
        error_code: str,
        now: datetime | None = None,
    ) -> bool:
        if not 1 <= retry_after_seconds <= 86_400:
            raise ValueError("Retry delay out of range")
        return self._complete_lease(
            report,
            "pending",
            _timestamp(_now(now) + timedelta(seconds=retry_after_seconds)),
            error_code,
        )

    def block(self, report: LeasedReport, *, error_code: str) -> bool:
        return self._complete_lease(report, "blocked", None, error_code)

    def _complete_lease(
        self,
        report: LeasedReport,
        target: str,
        next_attempt: str | None,
        error_code: str | None,
    ) -> bool:
        if error_code is not None and not re.fullmatch(r"[A-Z0-9_]{1,48}", error_code):
            raise ValueError("Error code must not contain response bodies or secrets")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """UPDATE device_report_outbox
                   SET delivery_state=?, next_attempt_at=COALESCE(?, next_attempt_at),
                       lease_token=NULL, lease_until=NULL, last_error_code=?
                   WHERE event_id=? AND delivery_state='leased' AND lease_token=?""",
                (target, next_attempt, error_code, report.event_id, report.lease_token),
            )
            connection.commit()
            return result.rowcount == 1

    def begin_execution(self, command_id: str, *, now: datetime | None = None) -> bool:
        """Only execute after cloud persisted ACK; marks execution before ECU I/O."""
        stamp = _now(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT execution_state, expires_at FROM device_commands
                   WHERE command_id=?""",
                (command_id,),
            ).fetchone()
            if row is None:
                raise DeviceExecutionStateError("Unknown device command")
            if row["execution_state"] != "received":
                return False
            acked = connection.execute(
                """SELECT 1 FROM device_report_outbox
                   WHERE command_id=? AND report_status='acknowledged'
                     AND delivery_state='delivered'""",
                (command_id,),
            ).fetchone()
            if acked is None:
                return False
            if datetime.fromisoformat(row["expires_at"]) <= stamp:
                connection.execute(
                    "UPDATE device_commands SET execution_state='expired' WHERE command_id=?",
                    (command_id,),
                )
                connection.commit()
                return False
            connection.execute(
                """UPDATE device_commands
                   SET execution_state='executing', started_at=? WHERE command_id=?""",
                (_timestamp(stamp), command_id),
            )
            connection.commit()
            return True

    def finish_execution(
        self,
        command_id: str,
        *,
        succeeded: bool,
        failure_code: str | None = None,
        now: datetime | None = None,
    ) -> str:
        """Atomically record observed ECU result and its outbound HTTP event."""
        if succeeded and failure_code is not None:
            raise ValueError("Success cannot carry a failure code")
        if not succeeded and (
            failure_code is None or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", failure_code)
        ):
            raise ValueError("Failure requires a safe failure_code")
        stamp = _now(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT execution_state FROM device_commands WHERE command_id=?",
                (command_id,),
            ).fetchone()
            if row is None or row["execution_state"] != "executing":
                raise DeviceExecutionStateError("Command is not in executing state")
            state = "succeeded" if succeeded else "failed"
            connection.execute(
                """UPDATE device_commands SET execution_state=?, finished_at=?,
                   failure_code=? WHERE command_id=?""",
                (state, _timestamp(stamp), failure_code, command_id),
            )
            event_id = self._insert_report(
                connection,
                command_id=command_id,
                status=state,
                now=stamp,
                failure_code=failure_code,
            )
            connection.commit()
            return event_id

    def recover_interrupted(self) -> int:
        """Do not replay potentially completed ECU effects after a crash."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """UPDATE device_commands SET execution_state='uncertain'
                   WHERE execution_state='executing'"""
            ).rowcount
            connection.commit()
        return changed

    def list_commands(
        self, *, states: tuple[ExecutionState, ...], limit: int = 30
    ) -> list[StoredCommand]:
        """List outstanding work; actual claim uses begin_execution under a write lock."""
        if not states or not 1 <= limit <= 100:
            raise ValueError("Invalid query parameters")
        placeholders = ",".join("?" for _ in states)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT command_id,command_type,execution_state,expires_at,failure_code "
                f"FROM device_commands WHERE execution_state IN ({placeholders}) "
                "ORDER BY received_at,command_id LIMIT ?",
                (*[state.value for state in states], limit),
            ).fetchall()
        return [
            StoredCommand(
                command_id=row["command_id"],
                state=ExecutionState(row["execution_state"]),
                command_type=row["command_type"],
                expires_at=datetime.fromisoformat(row["expires_at"]),
                failure_code=row["failure_code"],
            )
            for row in rows
        ]

    def mark_uncertain(self, command_id: str) -> bool:
        """No blind retry after an ambiguous ECU call."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE device_commands SET execution_state='uncertain' "
                "WHERE command_id=? AND execution_state='executing'",
                (command_id,),
            ).rowcount
            connection.commit()
        return updated == 1

    def reconcile_result(
        self,
        command_id: str,
        *,
        succeeded: bool,
        failure_code: str | None = None,
        now: datetime | None = None,
    ) -> str:
        """Apply an authoritative read-only ECU query result and enqueue one report.

        Only call after the Gateway proved an existing Body ECU journal entry.
        This method never issues a new ECU action.
        """
        if succeeded and failure_code is not None:
            raise ValueError("Success cannot carry failure code")
        if not succeeded and (
            failure_code is None or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", failure_code)
        ):
            raise ValueError("Failure requires a safe failure_code")
        stamp = _now(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT execution_state FROM device_commands WHERE command_id=?",
                (command_id,),
            ).fetchone()
            if row is None or row["execution_state"] not in {"executing", "uncertain"}:
                raise DeviceExecutionStateError("Command cannot be reconciled")
            status = "succeeded" if succeeded else "failed"
            connection.execute(
                "UPDATE device_commands SET execution_state=?,finished_at=?,failure_code=? "
                "WHERE command_id=?",
                (status, _timestamp(stamp), failure_code, command_id),
            )
            event_id = self._insert_report(
                connection,
                command_id=command_id,
                status=status,
                now=stamp,
                failure_code=failure_code,
            )
            connection.commit()
            return event_id

    def report_state(self, event_id: str) -> DeliveryState | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT delivery_state FROM device_report_outbox WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return DeliveryState(row["delivery_state"]) if row else None

    def report_count(self, command_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count(*) FROM device_report_outbox WHERE command_id=?",
                (command_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Cannot query device report count")
            return int(row[0])

    def requeue_blocked(self, event_id: str, *, now: datetime | None = None) -> bool:
        """Explicit operator action after fixing credentials or a business conflict."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """UPDATE device_report_outbox
                   SET delivery_state='pending', next_attempt_at=?, last_error_code=NULL
                   WHERE event_id=? AND delivery_state='blocked'""",
                (_timestamp(_now(now)), event_id),
            )
            connection.commit()
            return result.rowcount == 1
