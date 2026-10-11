from __future__ import annotations

import hashlib
import json
import random
import shutil
import sqlite3
import time
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from connected_vehicle.device_data import CommandReport
from connected_vehicle.remote_command.wire_contracts import DispatchPayload
from enterprise_platform.security.context import get_security_context
from simulators.vehicle_device.ownership import runtime_lock


class CapacityError(RuntimeError):
    """No MQTT ACK: let the durable broker retry after space/backlog recovers."""


def backoff(attempts: int, cap: float) -> float:
    base = min(cap / 1.2, 0.2 * 2 ** min(max(attempts, 0), 8))
    return float(base * random.uniform(0.8, 1.2))


class Store:
    """Single event-loop owner; every externally acknowledged change is committed first."""

    def __init__(
        self,
        path: Path,
        *,
        max_pending_commands: int = 1000,
        max_quarantine_records: int = 1000,
        min_free_bytes: int = 33554432,
        max_ledger_records: int = 100000,
    ) -> None:
        if (
            max_pending_commands < 1
            or max_quarantine_records < 1
            or min_free_bytes < 0
            or max_ledger_records < 1
        ):
            raise ValueError("invalid_device_capacity_limits")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.max_pending_commands = max_pending_commands
        self.max_quarantine_records = max_quarantine_records
        self.max_ledger_records = max_ledger_records
        self.min_free_bytes = min_free_bytes
        self.db = sqlite3.connect(path)
        try:
            self.db.row_factory = sqlite3.Row
            self._identity: tuple[str, str] | None = None
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA busy_timeout=5000")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS commands (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS reports (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, command_id TEXT NOT NULL,
                    payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS quarantine (
                    digest TEXT PRIMARY KEY, reason TEXT NOT NULL, received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_identity (
                    id INTEGER PRIMARY KEY CHECK(id=1), tenant_id TEXT NOT NULL,
                    vehicle_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archived_commands (
                    id TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS faults (name TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS report_replays (
                    operation_id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
                    actor TEXT NOT NULL, reason TEXT NOT NULL,
                    previous_error TEXT, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_reports_command_sequence
                    ON reports(command_id,sequence,state);
                CREATE INDEX IF NOT EXISTS ix_reports_pending
                    ON reports(state,next_attempt,sequence);
                CREATE INDEX IF NOT EXISTS ix_commands_state ON commands(state);
                CREATE INDEX IF NOT EXISTS ix_reports_unfinished ON reports(command_id)
                    WHERE state!='delivered';
            """)
            # Existing commands retain their exact legacy bytes across upgrades/retries.
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(commands)")}
            if "can_version" not in columns:
                self.db.execute(
                    "ALTER TABLE commands ADD COLUMN can_version INTEGER NOT NULL DEFAULT 1"
                )
                self.db.commit()
        except BaseException:
            self.db.close()
            raise

    def bind_identity(self, tenant_id: str, vehicle_id: str) -> None:
        expected = (tenant_id, vehicle_id)
        if self._identity is not None:
            if self._identity != expected:
                raise ValueError("device_database_identity_mismatch")
            return
        with self.db:
            existing = self.db.execute(
                "SELECT tenant_id,vehicle_id FROM device_identity WHERE id=1"
            ).fetchone()
            if existing is not None:
                if (existing["tenant_id"], existing["vehicle_id"]) != expected:
                    raise ValueError("device_database_identity_mismatch")
            else:
                # Upgrade an existing Day11 ledger without rewriting its commands.
                for row in self.db.execute("SELECT payload FROM commands"):
                    command = DispatchPayload.model_validate_json(row["payload"])
                    if (command.tenant_id, str(command.vehicle_id)) != expected:
                        raise ValueError("device_database_identity_mismatch")
                self.db.execute("INSERT INTO device_identity VALUES (1,?,?)", expected)
        self._identity = expected

    def close(self) -> None:
        self.db.close()

    def _check_space(self) -> None:
        if shutil.disk_usage(self.path.parent).free < self.min_free_bytes:
            raise CapacityError("device_disk_reserve_reached")

    def quarantine(self, payload: bytes, reason: str) -> None:
        digest = hashlib.sha256(payload).hexdigest()
        with self.db:
            if self.db.execute("SELECT 1 FROM quarantine WHERE digest=?", (digest,)).fetchone():
                return
            self._check_space()
            if (
                self.db.execute("SELECT count(*) FROM quarantine").fetchone()[0]
                >= self.max_quarantine_records
            ):
                raise CapacityError("device_quarantine_capacity_reached")
            self.db.execute(
                "INSERT OR IGNORE INTO quarantine VALUES (?, ?, ?)",
                (digest, reason, datetime.now(UTC).isoformat()),
            )

    def accept(self, command: DispatchPayload) -> bool:
        if self._identity is None:
            binding = self.db.execute(
                "SELECT tenant_id,vehicle_id FROM device_identity WHERE id=1"
            ).fetchone()
            if binding is not None:
                self._identity = (binding["tenant_id"], binding["vehicle_id"])
        if self._identity is not None and self._identity != (
            command.tenant_id,
            str(command.vehicle_id),
        ):
            raise ValueError("device_database_identity_mismatch")
        payload = command.model_dump_json()
        command_id = str(command.command_id)
        with self.db:
            previous = self.db.execute(
                "SELECT payload FROM commands WHERE id=?", (command_id,)
            ).fetchone()
            if previous:
                if previous["payload"] != payload:
                    raise ValueError("command_id_payload_conflict")
                return False
            archived = self.db.execute(
                "SELECT payload_sha256 FROM archived_commands WHERE id=?", (command_id,)
            ).fetchone()
            if archived:
                if archived[0] != hashlib.sha256(payload.encode()).hexdigest():
                    raise ValueError("command_id_payload_conflict")
                return False
            if (
                self.db.execute(
                    "SELECT (SELECT count(*) FROM commands)"
                    "+(SELECT count(*) FROM archived_commands)"
                    "+(SELECT count(*) FROM report_replays)"
                ).fetchone()[0]
                >= self.max_ledger_records
            ):
                raise CapacityError("device_ledger_capacity_reached_archive_or_expand")
            self._check_space()
            outstanding = self.db.execute(
                "SELECT count(*) FROM (SELECT id FROM commands WHERE state='pending' "
                "UNION SELECT command_id FROM reports WHERE state!='delivered')"
            ).fetchone()[0]
            if outstanding >= self.max_pending_commands:
                raise CapacityError("device_command_capacity_reached")
            self.db.execute(
                "INSERT INTO commands(id,payload,state,can_version) VALUES (?,?,'pending',2)",
                (command_id, payload),
            )
            self._report(command_id, "acknowledged")
        return True

    def _report(self, command_id: str, status: str, failure_code: str | None = None) -> None:
        report = CommandReport.model_validate(
            {
                "event_id": str(uuid4()),
                "status": status,
                "occurred_at": datetime.now(UTC),
                "failure_code": failure_code,
            }
        )
        self.db.execute(
            "INSERT INTO reports(command_id,payload) VALUES (?,?)",
            (command_id, report.model_dump_json()),
        )

    def pending_command(self) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.db.execute(
            "SELECT * FROM commands WHERE id=(SELECT id FROM commands "
            "WHERE state='pending' ORDER BY rowid LIMIT 1) AND next_attempt<=?",
            (time.time(),),
        ).fetchone()
        return row

    def finish(self, command_id: str, failure: str | None = None) -> None:
        with self.db:
            changed = self.db.execute(
                "UPDATE commands SET state=? WHERE id=? AND state='pending'",
                ("failed" if failure else "succeeded", command_id),
            ).rowcount
            if changed:
                self._report(command_id, "failed" if failure else "succeeded", failure)

    def command_retry(self, command_id: str, attempts: int) -> None:
        with self.db:
            self.db.execute(
                "UPDATE commands SET attempts=attempts+1,next_attempt=? WHERE id=?",
                (time.time() + backoff(attempts, 10), command_id),
            )

    def pending_report(self) -> sqlite3.Row | None:
        # A failed/quarantined ACK blocks its result until an operator repairs it.
        row: sqlite3.Row | None = self.db.execute(
            "SELECT r.* FROM reports r WHERE state='pending' AND next_attempt<=? "
            "AND NOT EXISTS (SELECT 1 FROM reports p WHERE p.command_id=r.command_id "
            "AND p.sequence<r.sequence AND p.state!='delivered') ORDER BY sequence LIMIT 1",
            (time.time(),),
        ).fetchone()
        return row

    def report_result(
        self,
        sequence: int,
        status: int | None,
        attempts: int,
        retry_after: float | None = None,
        *,
        error_code: str | None = None,
    ) -> None:
        if retry_after is not None and retry_after > 86400:
            error_code = "HTTP_RETRY_AFTER_TOO_LONG"
        delivered = error_code is None and status is not None and 200 <= status < 300
        auth_exhausted = status in (401, 403) and attempts >= 7
        blocked = (
            auth_exhausted
            or error_code is not None
            or (status is not None and 300 <= status < 500 and status not in (401, 403, 408, 429))
        )
        with self.db:
            self.db.execute(
                "UPDATE reports SET state=?, attempts=attempts+1,next_attempt=?,error=? "
                "WHERE sequence=?",
                (
                    "delivered" if delivered else "blocked" if blocked else "pending",
                    time.time() + max(backoff(attempts, 30), min(86400, max(0, retry_after or 0))),
                    None
                    if delivered
                    else "AUTH_RETRY_EXHAUSTED"
                    if auth_exhausted
                    else error_code or str(status or "transport_error"),
                    sequence,
                ),
            )

    def consume_fault(self, name: str) -> bool:
        with self.db:
            changed = self.db.execute("INSERT OR IGNORE INTO faults VALUES (?)", (name,)).rowcount
        return bool(changed)

    def requeue_report(
        self,
        *,
        event_id: str,
        operation_id: str,
        actor: str,
        reason: str,
        tenant_id: str,
        vehicle_id: str,
    ) -> bool:
        event_id, operation_id = str(UUID(event_id)), str(UUID(operation_id))
        if (
            not actor.strip()
            or len(actor) > 128
            or not reason.strip()
            or len(reason) > 512
            or any(ord(char) < 32 for char in actor + reason)
        ):
            raise ValueError("replay_actor_and_reason_required")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            identity = self.db.execute(
                "SELECT tenant_id,vehicle_id FROM device_identity WHERE id=1"
            ).fetchone()
            context = get_security_context()
            if (
                identity is None
                or tuple(identity) != (tenant_id, vehicle_id)
                or (context is not None and context.principal.tenant_id != tenant_id)
            ):
                raise ValueError("replay_identity_mismatch")
            existing = self.db.execute(
                "SELECT event_id,actor,reason FROM report_replays WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != (event_id, actor, reason):
                    raise ValueError("replay_operation_id_conflict")
                return False
            records = self.db.execute(
                "SELECT (SELECT count(*) FROM commands)"
                "+(SELECT count(*) FROM archived_commands)"
                "+(SELECT count(*) FROM report_replays)"
            ).fetchone()[0]
            if records >= self.max_ledger_records:
                raise CapacityError("device_ledger_capacity_reached_archive_or_expand")
            report = self.db.execute(
                "SELECT sequence,state,error FROM reports "
                "WHERE json_extract(payload,'$.event_id')=?",
                (event_id,),
            ).fetchone()
            if report is None or report["state"] != "blocked":
                raise ValueError("replay_requires_blocked_event")
            self.db.execute(
                "UPDATE reports SET state='pending',next_attempt=0 WHERE sequence=?",
                (report["sequence"],),
            )
            self.db.execute(
                "INSERT INTO report_replays VALUES (?,?,?,?,?,?)",
                (
                    operation_id,
                    event_id,
                    actor,
                    reason,
                    report["error"],
                    datetime.now(UTC).isoformat(),
                ),
            )
        return True

    def reconcile(
        self,
        requeue: bool = False,
        *,
        limit: int = 1000,
        offset: int = 0,
    ) -> dict[str, object]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("invalid_reconciliation_page")
        if requeue:
            raise ValueError("bulk_replay_disabled_use_requeue_report")
        with self.db:
            self.db.execute("BEGIN")
            counts = {
                table: self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("commands", "reports", "quarantine")
            }
            return {
                "counts": counts,
                "replay_audit": [
                    dict(row)
                    for row in self.db.execute(
                        "SELECT * FROM report_replays ORDER BY rowid LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                ],
                "health": {
                    "command_states": {
                        row[0]: row[1]
                        for row in self.db.execute(
                            "SELECT state,count(*) FROM commands GROUP BY state"
                        )
                    },
                    "report_states": {
                        row[0]: row[1]
                        for row in self.db.execute(
                            "SELECT state,count(*) FROM reports GROUP BY state"
                        )
                    },
                    "report_attempts": self.db.execute(
                        "SELECT coalesce(sum(attempts),0) FROM reports"
                    ).fetchone()[0],
                    "oldest_unfinished_report_at": self.db.execute(
                        "SELECT min(json_extract(payload,'$.occurred_at')) FROM reports "
                        "WHERE state!='delivered'"
                    ).fetchone()[0],
                    "sqlite_bytes": self.db.execute("PRAGMA page_count").fetchone()[0]
                    * self.db.execute("PRAGMA page_size").fetchone()[0],
                    "disk_free_bytes": shutil.disk_usage(self.path.parent).free,
                    "archived_command_count": self.db.execute(
                        "SELECT count(*) FROM archived_commands"
                    ).fetchone()[0],
                    "ledger_capacity": self.max_ledger_records,
                    "ledger_records": self.db.execute(
                        "SELECT (SELECT count(*) FROM commands)"
                        "+(SELECT count(*) FROM archived_commands)"
                        "+(SELECT count(*) FROM report_replays)"
                    ).fetchone()[0],
                    "auth_blocked_reports": self.db.execute(
                        "SELECT count(*) FROM reports WHERE state='blocked' "
                        "AND error='AUTH_RETRY_EXHAUSTED'"
                    ).fetchone()[0],
                },
                "page": {"limit": limit, "offset": offset},
                "commands": [
                    dict(row)
                    for row in self.db.execute(
                        "SELECT id,state,attempts FROM commands ORDER BY rowid LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                ],
                "reports": [
                    {
                        key: row[key]
                        for key in (
                            "sequence",
                            "command_id",
                            "state",
                            "attempts",
                            "error",
                            "next_attempt",
                        )
                    }
                    | {
                        key: json.loads(row["payload"])[key]
                        for key in ("event_id", "status", "failure_code")
                    }
                    for row in self.db.execute(
                        "SELECT * FROM reports ORDER BY sequence LIMIT ? OFFSET ?", (limit, offset)
                    )
                ],
                "quarantine": [
                    dict(row)
                    for row in self.db.execute(
                        "SELECT * FROM quarantine ORDER BY rowid LIMIT ? OFFSET ?", (limit, offset)
                    )
                ],
            }


def print_reconciliation(
    path: Path,
    requeue: bool,
    limit: int = 1000,
    offset: int = 0,
    *,
    event_id: str | None = None,
    operation_id: str | None = None,
    actor: str | None = None,
    reason: str | None = None,
    tenant_id: str | None = None,
    vehicle_id: str | None = None,
) -> None:
    with runtime_lock(path) if requeue else nullcontext():
        store = Store(path)
        try:
            if requeue:
                if (
                    event_id is None
                    or operation_id is None
                    or actor is None
                    or reason is None
                    or tenant_id is None
                    or vehicle_id is None
                ):
                    raise ValueError("scoped_replay_metadata_required")
                store.requeue_report(
                    event_id=event_id,
                    operation_id=operation_id,
                    actor=actor,
                    reason=reason,
                    tenant_id=tenant_id,
                    vehicle_id=vehicle_id,
                )
            print(json.dumps(store.reconcile(limit=limit, offset=offset), indent=2))
        finally:
            store.close()
