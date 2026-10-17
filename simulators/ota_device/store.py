from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from connected_vehicle.ota.execution_contracts import ClaimResult, OTAReport


@contextmanager
def exclusive(root: Path) -> Iterator[None]:
    if root.is_symlink():
        raise ValueError("Device state directory must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    path = root / "agent.lock"
    if path.is_symlink():
        raise ValueError("Unsafe process lock path")
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class DeviceStore:
    def __init__(
        self,
        root: Path,
        *,
        tenant: str,
        vehicle: str,
        ecu: str,
        device: str,
        ecu_type: str,
        hardware_version: str,
    ) -> None:
        for value in (vehicle, ecu):
            if str(UUID(value)) != value:
                raise ValueError("Canonical device ownership IDs required")
        self.root = root
        if not ecu_type or not hardware_version:
            raise ValueError("Trusted hardware binding required")
        self.binding = dict(
            tenant=tenant,
            vehicle=vehicle,
            ecu=ecu,
            device=device,
            ecu_type=ecu_type,
            hardware_version=hardware_version,
        )
        path = root / "device.sqlite3"
        if path.is_symlink():
            raise ValueError("Unsafe SQLite state path")
        self.db = sqlite3.connect(path, timeout=1)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY,data TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY,operation TEXT NOT NULL,
            claim TEXT,state TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS reports (event_id TEXT PRIMARY KEY,job_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,payload TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0,
            UNIQUE(job_id,sequence));
          CREATE TABLE IF NOT EXISTS active (id INTEGER PRIMARY KEY,job_id TEXT NOT NULL,
            sha256 TEXT NOT NULL,version TEXT NOT NULL,security_version INTEGER NOT NULL,
            installations INTEGER NOT NULL);""")
        encoded = json.dumps(self.binding, sort_keys=True)
        row = self.db.execute("SELECT data FROM identity WHERE id=1").fetchone()
        if row is not None and row[0] != encoded:
            self.db.close()
            raise ValueError("Persisted device ownership mismatch")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO identity VALUES (1,?)", (encoded,))
        active = self.active()
        if active and self.image_digest(active["sha256"]) != active["sha256"]:
            self.db.close()
            raise ValueError("Active image is corrupt; operator reconciliation required")

    def close(self) -> None:
        self.db.close()

    def active(self) -> dict[str, object] | None:
        row = self.db.execute("SELECT * FROM active WHERE id=1").fetchone()
        return dict(row) if row is not None else None

    def image_digest(self, checksum: object) -> str:
        if (
            not isinstance(checksum, str)
            or len(checksum) != 64
            or any(c not in "0123456789abcdef" for c in checksum)
        ):
            raise ValueError("Invalid image identity")
        path = self.root / "images" / (checksum + ".bin")
        if path.is_symlink():
            raise ValueError("Unsafe image path")
        if path.stat().st_size > 32 * 1024**2:
            raise ValueError("Oversized local bank")
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def prepare(self, job: str) -> str:
        if str(UUID(job)) != job:
            raise ValueError("Invalid job identity")
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO jobs VALUES (?,?,NULL,'new')", (job, str(uuid4()))
            )
        row = self.db.execute("SELECT operation FROM jobs WHERE id=?", (job,)).fetchone()
        return str(row[0])

    def unfinished(self) -> str | None:
        row = self.db.execute("""SELECT j.id FROM jobs j WHERE
            j.state IN ('new','claimed','downloaded','installing') OR
            EXISTS (SELECT 1 FROM reports r WHERE r.job_id=j.id AND r.delivered=0)
            ORDER BY j.id LIMIT 1""").fetchone()
        return str(row[0]) if row else None

    def accept(self, claim: ClaimResult) -> None:
        job = claim.job
        if (
            claim.manifest.tenant_id != self.binding["tenant"]
            or str(job.vehicle_id) != self.binding["vehicle"]
            or str(job.ecu_id) != self.binding["ecu"]
            or claim.device_id != self.binding["device"]
            or job.release_id != claim.manifest.release_id
            or claim.manifest.ecu_type != self.binding["ecu_type"]
            or claim.manifest.hardware_version != self.binding["hardware_version"]
        ):
            raise ValueError("Cloud claim does not match configured device ownership")
        row = self.db.execute("SELECT claim FROM jobs WHERE id=?", (str(job.id),)).fetchone()
        if row is None:
            raise ValueError("Claim was not prepared locally")
        encoded = json.dumps(
            dict(
                manifest=claim.manifest.model_dump(mode="json"),
                signature=claim.signature,
                claim_token=str(claim.claim_token),
            ),
            sort_keys=True,
        )
        if row[0] is not None and row[0] != encoded:
            raise ValueError("Persistent claim content changed")
        with self.db:
            self.db.execute(
                "UPDATE jobs SET claim=?,state=CASE WHEN state='new' THEN 'claimed' ELSE state END "
                "WHERE id=?",
                (encoded, str(job.id)),
            )

    def state(self, job: str) -> str:
        return str(self.db.execute("SELECT state FROM jobs WHERE id=?", (job,)).fetchone()[0])

    def downloaded(self, job: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE jobs SET state='downloaded' WHERE id=? AND state='claimed'", (job,)
            )

    def enqueue(
        self,
        claim: ClaimResult,
        status: Literal["installing", "succeeded", "failed"],
        failure: Literal["health_failed"] | None = None,
    ) -> None:
        job = str(claim.job.id)
        sequence = 1 if status == "installing" else 2
        existing = self.db.execute(
            "SELECT 1 FROM reports WHERE job_id=? AND sequence=?", (job, sequence)
        ).fetchone()
        if existing:
            return
        report = OTAReport(
            event_id=uuid4(),
            claim_token=claim.claim_token,
            sequence=sequence,
            status=status,
            occurred_at=datetime.now(UTC),
            observed_sha256=claim.manifest.sha256 if status == "succeeded" else None,
            failure_code=failure,
        )
        self.db.execute(
            "INSERT INTO reports(event_id,job_id,sequence,payload) VALUES (?,?,?,?)",
            (str(report.event_id), job, sequence, report.model_dump_json()),
        )

    def installing(self, claim: ClaimResult) -> None:
        with self.db:
            self.enqueue(claim, "installing")
            self.db.execute(
                "UPDATE jobs SET state='installing' WHERE id=? AND state='downloaded'",
                (str(claim.job.id),),
            )

    def activate(self, claim: ClaimResult, *, healthy: bool) -> None:
        job, manifest = str(claim.job.id), claim.manifest
        if self.image_digest(manifest.sha256) != manifest.sha256:
            raise ValueError("Staged image changed before activation")
        previous = self.active()
        with self.db:
            if self.state(job) in {"installed", "failed", "reported"}:
                return
            if self.state(job) != "installing":
                raise ValueError("Installing report must precede activation")
            acknowledged = self.db.execute(
                "SELECT delivered FROM reports WHERE job_id=? AND sequence=1", (job,)
            ).fetchone()
            if acknowledged is None or acknowledged[0] != 1:
                raise ValueError("Installing report must be confirmed before activation")
            if previous and manifest.security_version <= int(str(previous["security_version"])):
                raise ValueError("Device anti-rollback floor would regress")
            if healthy:
                count = int(str(previous["installations"])) + 1 if previous else 1
                self.db.execute(
                    "INSERT OR REPLACE INTO active VALUES (1,?,?,?,?,?)",
                    (job, manifest.sha256, manifest.version, manifest.security_version, count),
                )
                self.enqueue(claim, "succeeded")
                self.db.execute("UPDATE jobs SET state='installed' WHERE id=?", (job,))
            else:
                self.enqueue(claim, "failed", "health_failed")
                self.db.execute("UPDATE jobs SET state='failed' WHERE id=?", (job,))

    def pending(self, job: str) -> list[tuple[str, str]]:
        return [
            (str(row[0]), str(row[1]))
            for row in self.db.execute(
                "SELECT event_id,payload FROM reports WHERE job_id=? "
                "AND delivered=0 ORDER BY sequence",
                (job,),
            )
        ]

    def delivered(self, event: str) -> None:
        with self.db:
            self.db.execute("UPDATE reports SET delivered=1 WHERE event_id=?", (event,))
