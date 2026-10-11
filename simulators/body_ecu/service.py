from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from simulators.vehicle_device.can import Frame, decode_command


class BodyStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS executions (
                    command_id TEXT PRIMARY KEY, data BLOB NOT NULL, result INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS body (
                    id INTEGER PRIMARY KEY CHECK(id=1), locked INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO body VALUES (1,0);
                CREATE TABLE IF NOT EXISTS faults (name TEXT PRIMARY KEY);
            """)
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def execute(self, frame: Frame) -> Frame:
        opcode, expires = decode_command(frame)
        command_id = str(frame.command_id)
        with self.db:
            previous = self.db.execute(
                "SELECT data,result FROM executions WHERE command_id=?", (command_id,)
            ).fetchone()
            if previous:
                result = int(previous[1]) if bytes(previous[0]) == frame.data else 3
            else:
                result = 2 if expires <= time.time() else 0 if opcode in (1, 2) else 1
                if result == 0:
                    self.db.execute("UPDATE body SET locked=? WHERE id=1", (int(opcode == 1),))
                self.db.execute(
                    "INSERT INTO executions VALUES (?,?,?)", (command_id, frame.data, result)
                )
        return Frame(frame.command_id, 0x180, bytes([result]))

    def reconcile(self, *, limit: int = 1000, offset: int = 0) -> dict[str, object]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("invalid_reconciliation_page")
        with self.db:
            self.db.execute("BEGIN")
            return {
                "count": self.db.execute("SELECT count(*) FROM executions").fetchone()[0],
                "page": {"limit": limit, "offset": offset},
                "locked": bool(self.db.execute("SELECT locked FROM body WHERE id=1").fetchone()[0]),
                "executions": [
                    {"command_id": row[0], "result_code": row[1]}
                    for row in self.db.execute(
                        "SELECT command_id,result FROM executions ORDER BY rowid LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                ],
            }

    def consume_fault(self) -> bool:
        with self.db:
            changed = self.db.execute(
                "INSERT OR IGNORE INTO faults VALUES ('after_execution')"
            ).rowcount
        return bool(changed)
