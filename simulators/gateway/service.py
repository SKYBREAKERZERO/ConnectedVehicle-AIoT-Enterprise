from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import time
from pathlib import Path

from enterprise_platform.runtime.process import termination_signals
from simulators.vehicle_device.can import Frame, VirtualCAN, decode_command
from simulators.vehicle_device.ownership import runtime_lock
from simulators.vehicle_device.store import backoff


class GatewayStore:
    """Durable routing ledger, separate from T-Box reports and Body ECU execution."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS routes (
                    command_id TEXT PRIMARY KEY, frame BLOB NOT NULL, response BLOB,
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS faults (name TEXT PRIMARY KEY);
            """)
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def accept(self, frame: Frame) -> tuple[bool, Frame | None]:
        decode_command(frame)
        with self.db:
            previous = self.db.execute(
                "SELECT frame,response FROM routes WHERE command_id=?", (str(frame.command_id),)
            ).fetchone()
            if previous:
                if bytes(previous[0]) != frame.encode():
                    return False, Frame(frame.command_id, 0x180, b"\x03")
                return False, Frame.decode(bytes(previous[1])) if previous[1] is not None else None
            self.db.execute(
                "INSERT INTO routes(command_id,frame) VALUES (?,?)",
                (str(frame.command_id), frame.encode()),
            )
        return True, None

    def pending(self) -> list[Frame]:
        with self.db:
            rows = self.db.execute(
                "SELECT command_id,frame,attempts FROM routes WHERE command_id=("
                "SELECT command_id FROM routes WHERE response IS NULL ORDER BY rowid LIMIT 1) "
                "AND next_attempt<=?",
                (time.time(),),
            ).fetchall()
            for row in rows:
                self.db.execute(
                    "UPDATE routes SET attempts=attempts+1,next_attempt=? WHERE command_id=?",
                    (time.time() + backoff(row[2], 5), row[0]),
                )
        return [Frame.decode(bytes(row[1])) for row in rows]

    def finish(self, frame: Frame) -> bool:
        if (
            frame.arbitration_id != 0x180
            or len(frame.data) != 1
            or frame.data[0] not in (0, 1, 2, 3)
        ):
            raise ValueError("invalid_gateway_response")
        with self.db:
            row = self.db.execute(
                "SELECT response FROM routes WHERE command_id=?", (str(frame.command_id),)
            ).fetchone()
            if row is None or (row[0] is not None and bytes(row[0]) != frame.encode()):
                return False
            self.db.execute(
                "UPDATE routes SET response=? WHERE command_id=?",
                (frame.encode(), str(frame.command_id)),
            )
        return True

    def consume_fault(self) -> bool:
        with self.db:
            changed = self.db.execute(
                "INSERT OR IGNORE INTO faults VALUES ('route_commit')"
            ).rowcount
        return bool(changed)

    def reconcile(self, *, limit: int = 1000, offset: int = 0) -> dict[str, object]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("invalid_reconciliation_page")
        with self.db:
            self.db.execute("BEGIN")
            return {
                "count": self.db.execute("SELECT count(*) FROM routes").fetchone()[0],
                "page": {"limit": limit, "offset": offset},
                "routes": [
                    {
                        "command_id": row[0],
                        "state": "completed" if row[1] is not None else "pending",
                        "result_code": Frame.decode(bytes(row[1])).data[0]
                        if row[1] is not None
                        else None,
                        "attempts": row[2],
                    }
                    for row in self.db.execute(
                        "SELECT command_id,response,attempts FROM routes "
                        "ORDER BY rowid LIMIT ? OFFSET ?",
                        (limit, offset),
                    )
                ],
            }


async def _serve(
    database: Path,
    port: int,
    tbox_port: int,
    body_bus_port: int,
    body_port: int,
    crash: bool,
) -> None:
    store = GatewayStore(database)
    try:
        front = VirtualCAN(port, tbox_port)
    except BaseException:
        store.close()
        raise
    try:
        back = VirtualCAN(body_bus_port, body_port)
    except BaseException:
        front.close()
        store.close()
        raise
    stop = asyncio.Event()

    async def receive_commands() -> None:
        while True:
            frame = await front.receive()
            try:
                accepted, response = store.accept(frame)
                if accepted and crash and store.consume_fault():
                    os._exit(72)
                if response is not None:
                    await front.send(response)
            except ValueError:
                logging.warning("gateway_invalid_command")

    async def forward() -> None:
        while True:
            for frame in store.pending():
                await back.send(frame)
            await asyncio.sleep(0.05)

    async def receive_results() -> None:
        while True:
            frame = await back.receive()
            try:
                if store.finish(frame):
                    await front.send(frame)
            except ValueError:
                logging.warning("gateway_invalid_result")

    try:
        with termination_signals(stop):
            logging.info("gateway_ready")
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(receive_commands()),
                    group.create_task(forward()),
                    group.create_task(receive_results()),
                ]
                await stop.wait()
                for task in tasks:
                    task.cancel()
    finally:
        front.close()
        back.close()
        store.close()
        logging.info("gateway_stopped")


async def serve(
    database: Path, port: int, tbox_port: int, body_bus_port: int, body_port: int, crash: bool
) -> None:
    with runtime_lock(database, wait_seconds=1):
        await _serve(database, port, tbox_port, body_bus_port, body_port, crash)
