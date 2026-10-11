from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from simulators.vehicle_device.ownership import runtime_lock


def snapshot(source: Path, destination: Path, *, timeout: float = 30) -> dict[str, object]:
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
            }
        finally:
            temporary.unlink(missing_ok=True)


def archive(source: Path, destination: Path, *, before: datetime) -> dict[str, object]:
    """Offline verified snapshot before bounded pruning; retain identity, dedup and audit."""
    if before.tzinfo is None or before > datetime.now(UTC):
        raise ValueError("archive_cutoff_must_be_past_and_timezone_aware")
    with runtime_lock(source):
        result = snapshot(source, destination)
        with sqlite3.connect(source) as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                """SELECT id,payload FROM commands c
                WHERE state IN ('succeeded','failed')
                AND julianday(json_extract(payload,'$.expires_at')) < julianday(?)
                AND NOT EXISTS (SELECT 1 FROM reports r
                    WHERE r.command_id=c.id AND r.state!='delivered')
                ORDER BY rowid LIMIT 1000""",
                (before.isoformat(),),
            ).fetchall()
            for command_id, payload in rows:
                db.execute(
                    "INSERT INTO archived_commands VALUES (?,?)",
                    (command_id, hashlib.sha256(payload.encode()).hexdigest()),
                )
                db.execute("DELETE FROM reports WHERE command_id=?", (command_id,))
                db.execute("DELETE FROM commands WHERE id=?", (command_id,))
            db.commit()
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("VACUUM")
        return result | {"archived_commands": len(rows)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Snapshot or restore a device SQLite ledger.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--archive-before", type=datetime.fromisoformat)
    args = parser.parse_args()
    result = (
        archive(args.source, args.destination, before=args.archive_before)
        if args.archive_before
        else snapshot(args.source, args.destination)
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
