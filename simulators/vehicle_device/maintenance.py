from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import tempfile
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import TypedDict
from uuid import UUID

from simulators.vehicle_device.ownership import runtime_lock


class RestoreAudit(TypedDict):
    operation_id: str
    actor: str
    reason: str


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(
    source: Path,
    destination: Path,
    *,
    timeout: float = 30,
    expected_sha256: str | None = None,
    restore_audit: RestoreAudit | None = None,
) -> dict[str, object]:
    """Online SQLite snapshot, also usable to restore into a new offline ledger.

    Copies committed WAL data through SQLite; publishes only a verified, complete
    snapshot. Hard-link publication is atomic and cannot overwrite an existing path.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("invalid_backup_timeout")
    source = source.resolve()
    destination = destination.resolve()
    if source == destination:
        raise ValueError("backup_source_equals_destination")
    if not source.is_file():
        raise FileNotFoundError(source)
    if expected_sha256 is not None:
        if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
            raise ValueError("invalid_expected_sha256")
        if digest(source) != expected_sha256:
            raise ValueError("backup_digest_mismatch")
        if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-journal")):
            raise ValueError("restore_requires_sealed_backup")
    if restore_audit is not None:
        if expected_sha256 is None:
            raise ValueError("restore_requires_expected_digest")
        UUID(restore_audit["operation_id"])
        for value, limit in ((restore_audit["actor"], 128), (restore_audit["reason"], 512)):
            if not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
                raise ValueError("restore_audit_metadata_required")
    with runtime_lock(destination):
        if destination.exists():
            raise FileExistsError(destination)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".device-backup-", suffix=".sqlite", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        deadline = monotonic() + timeout

        def progress(status: int, remaining: int, total: int) -> None:
            if monotonic() >= deadline:
                raise TimeoutError("device_backup_timeout")

        try:
            reader = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
            try:
                writer = sqlite3.connect(temporary)
                try:
                    reader.backup(writer, pages=128, progress=progress, sleep=0.05)
                    writer.execute("PRAGMA journal_mode=DELETE")
                    tables = {
                        row[0]
                        for row in writer.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                    }
                    if not any(
                        required <= tables
                        for required in (
                            {"commands", "reports", "device_identity"},
                            {"routes"},
                            {"executions", "body"},
                            {"device_commands", "device_report_outbox", "device_identity"},
                        )
                    ):
                        raise ValueError("unsupported_device_ledger")
                    if writer.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                        raise ValueError("device_backup_integrity_failed")
                    if expected_sha256 is not None and digest(source) != expected_sha256:
                        raise ValueError("backup_changed_during_restore")
                    if restore_audit is not None:
                        with writer:
                            writer.execute("""CREATE TABLE IF NOT EXISTS maintenance_audit (
                                operation_id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                                reason TEXT NOT NULL, source_sha256 TEXT NOT NULL,
                                created_at TEXT NOT NULL)""")
                            writer.execute(
                                "INSERT INTO maintenance_audit VALUES (?,?,?,?,?)",
                                (
                                    restore_audit["operation_id"],
                                    restore_audit["actor"],
                                    restore_audit["reason"],
                                    expected_sha256,
                                    datetime.now(UTC).isoformat(),
                                ),
                            )
                finally:
                    writer.close()
            finally:
                reader.close()
            # Flush contents before exposing the final snapshot name.
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            os.link(temporary, destination)
            return {
                "source": str(source),
                "destination": str(destination),
                "integrity": "ok",
                "bytes": destination.stat().st_size,
                "sha256": digest(destination),
            }
        finally:
            temporary.unlink(missing_ok=True)


def archive(
    source: Path, destination: Path, *, before: datetime, online: bool = False, batch: int = 100
) -> dict[str, object]:
    """Snapshot first; prune only rows present in that snapshot and unchanged live."""
    source, destination = source.resolve(), destination.resolve()
    if before.tzinfo is None or before > datetime.now(UTC) or not 1 <= batch <= 1000:
        raise ValueError("invalid_archive_cutoff_or_batch")
    with (
        runtime_lock(Path(str(source) + ".archive")),
        nullcontext() if online else runtime_lock(source),
    ):
        result = snapshot(source, destination)
        with sqlite3.connect(destination.as_uri() + "?mode=ro", uri=True) as saved:
            rows = saved.execute(
                """SELECT id,payload,state FROM commands c
                WHERE state IN ('succeeded','failed')
                AND julianday(json_extract(payload,'$.expires_at')) < julianday(?)
                AND NOT EXISTS (SELECT 1 FROM reports r
                    WHERE r.command_id=c.id AND r.state!='delivered')
                ORDER BY rowid LIMIT ?""",
                (before.isoformat(), batch),
            ).fetchall()
            reports = {
                row[0]: saved.execute(
                    "SELECT * FROM reports WHERE command_id=? ORDER BY sequence", (row[0],)
                ).fetchall()
                for row in rows
            }
        count = 0
        with sqlite3.connect(source, timeout=1) as db:
            db.execute("PRAGMA busy_timeout=1000")
            db.execute("BEGIN IMMEDIATE")
            for command_id, payload, state in rows:
                live = db.execute(
                    "SELECT payload,state FROM commands WHERE id=?", (command_id,)
                ).fetchone()
                current_reports = db.execute(
                    "SELECT * FROM reports WHERE command_id=? ORDER BY sequence", (command_id,)
                ).fetchall()
                if live != (payload, state) or current_reports != reports[command_id]:
                    continue
                summary = hashlib.sha256(payload.encode()).hexdigest()
                existing = db.execute(
                    "SELECT payload_sha256 FROM archived_commands WHERE id=?", (command_id,)
                ).fetchone()
                if existing is not None and existing[0] != summary:
                    raise ValueError("archive_digest_conflict")
                db.execute(
                    "INSERT OR IGNORE INTO archived_commands VALUES (?,?)",
                    (command_id, summary),
                )
                db.execute("DELETE FROM reports WHERE command_id=?", (command_id,))
                db.execute("DELETE FROM commands WHERE id=?", (command_id,))
                count += 1
            db.commit()
            # Online mode never takes a long exclusive VACUUM or truncating checkpoint.
            if not online:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                db.execute("VACUUM")
        return result | {"archived_commands": count, "online": online}


def main() -> None:
    parser = argparse.ArgumentParser(description="Snapshot or restore a device SQLite ledger.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--archive-before", type=datetime.fromisoformat)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--batch", type=int, default=100)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--operation-id")
    parser.add_argument("--actor")
    parser.add_argument("--reason")
    args = parser.parse_args()
    if args.online and not args.archive_before:
        parser.error("--online requires --archive-before")
    if args.expected_sha256 and (
        args.archive_before or not all((args.operation_id, args.actor, args.reason))
    ):
        parser.error("restore requires operation ID, actor and reason, without archive")
    if not args.expected_sha256 and any((args.operation_id, args.actor, args.reason)):
        parser.error("restore audit requires expected SHA256")
    result = (
        archive(
            args.source.resolve(),
            args.destination.resolve(),
            before=args.archive_before,
            online=args.online,
            batch=args.batch,
        )
        if args.archive_before
        else snapshot(
            args.source,
            args.destination,
            expected_sha256=args.expected_sha256,
            restore_audit=RestoreAudit(
                operation_id=args.operation_id, actor=args.actor, reason=args.reason
            )
            if args.expected_sha256
            else None,
        )
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
