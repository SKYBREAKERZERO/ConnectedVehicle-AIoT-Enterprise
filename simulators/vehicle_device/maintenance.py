from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import tempfile
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Snapshot or restore a device SQLite ledger.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.source, args.destination), indent=2))


if __name__ == "__main__":
    main()
