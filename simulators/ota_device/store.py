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

from connected_vehicle.ota.execution_contracts import ClaimResult, InstallationProof, OTAReport


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
        max_artifact_bytes: int = 32 * 1024**2,
    ) -> None:
        for value in (vehicle, ecu):
            if str(UUID(value)) != value:
                raise ValueError("Canonical device ownership IDs required")
        self.root = root
        if not 1 <= max_artifact_bytes <= 256 * 1024**2:
            raise ValueError("Invalid device artifact quota")
        self.max_artifact_bytes = max_artifact_bytes
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
        self.db.executescript("""CREATE TABLE IF NOT EXISTS banks(name TEXT PRIMARY KEY,
          sha256 TEXT,version TEXT,security_version INTEGER,job_id TEXT,state TEXT NOT NULL);
          INSERT OR IGNORE INTO banks(name,state) VALUES('A','empty'),('B','empty');
          CREATE TABLE IF NOT EXISTS boots(job_id TEXT PRIMARY KEY,bank TEXT NOT NULL,
            challenge TEXT NOT NULL,proof TEXT);
          CREATE TABLE IF NOT EXISTS local_audit(operation TEXT PRIMARY KEY,
            payload TEXT NOT NULL);""")
        if "bank" not in {row[1] for row in self.db.execute("PRAGMA table_info(active)")}:
            self.db.execute("ALTER TABLE active ADD COLUMN bank TEXT NOT NULL DEFAULT 'A'")
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
        if active:
            with self.db:
                self.db.execute(
                    (
                        "UPDATE banks SET "
                        "sha256=?,version=?,security_version=?,job_id=?,state='confirmed' "
                        "WHERE name=? AND state='empty'"
                    ),
                    (
                        active["sha256"],
                        active["version"],
                        active["security_version"],
                        active["job_id"],
                        active["bank"],
                    ),
                )

    def bootstrap(self, image: Path, checksum: str, version: str, security_version: int) -> None:
        if self.active() is not None:
            return
        if (
            type(security_version) is not int
            or security_version < 0
            or image.is_symlink()
            or image.stat().st_size > self.max_artifact_bytes
        ):
            raise ValueError("Invalid trusted factory image/counter")
        images = self.root / "images"
        if images.is_symlink():
            raise ValueError("Unsafe bank directory")
        images.mkdir(exist_ok=True)
        target = images / (checksum + ".bin")
        if (
            len(checksum) != 64
            or any(c not in "0123456789abcdef" for c in checksum)
            or target.is_symlink()
        ):
            raise ValueError("Unsafe factory checksum")
        import os

        with image.open("rb") as source:
            if source.read(7) != b"CVOTA1\n":
                raise ValueError("Factory image did not pass local boot check")
            source.seek(0)
            if hashlib.file_digest(source, "sha256").hexdigest() != checksum:
                raise ValueError("Factory image differs from controlled bootstrap digest")
            if target.exists():
                if self.image_digest(checksum) != checksum:
                    raise ValueError("Existing factory image is corrupt")
            else:
                source.seek(0)
                partial = images / ".factory.part"
                if partial.is_symlink():
                    raise ValueError("Unsafe factory staging path")
                with partial.open("wb") as out:
                    while chunk := source.read(65536):
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(partial, target)
                if sys.platform != "win32":
                    fd = os.open(images, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
        with self.db:
            self.db.execute(
                "INSERT INTO active VALUES(1,'factory',?,?,?,?, 'A')",
                (checksum, version, security_version, 0),
            )
            self.db.execute(
                (
                    "UPDATE banks SET "
                    "sha256=?,version=?,security_version=?,job_id='factory',state='con"
                    "firmed' WHERE name='A'"
                ),
                (checksum, version, security_version),
            )
            self.db.execute(
                "INSERT INTO local_audit VALUES(?,?)",
                (
                    "factory-bootstrap",
                    json.dumps(
                        dict(sha256=checksum, version=version, security_version=security_version)
                    ),
                ),
            )

    def stage(self, claim: ClaimResult) -> str:
        if claim.install_challenge is None:
            raise ValueError("Server boot challenge required")
        job = str(claim.job.id)
        ack = self.db.execute(
            "SELECT delivered FROM reports WHERE job_id=? AND sequence=1", (job,)
        ).fetchone()
        if ack is None or ack[0] != 1:
            raise ValueError("Installing report must be confirmed before boot staging")
        existing = self.db.execute(
            "SELECT bank,challenge FROM boots WHERE job_id=?", (job,)
        ).fetchone()
        if existing:
            if existing["challenge"] != str(claim.install_challenge):
                raise ValueError("Boot challenge changed")
            return str(existing["bank"])
        previous = self.active()
        bank = "B" if previous and previous["bank"] == "A" else "A"
        with self.db:
            self.db.execute(
                (
                    "UPDATE banks SET "
                    "sha256=?,version=?,security_version=?,job_id=?,state='pending_boo"
                    "t' WHERE name=?"
                ),
                (
                    claim.manifest.sha256,
                    claim.manifest.version,
                    claim.manifest.security_version,
                    job,
                    bank,
                ),
            )
            self.db.execute(
                "INSERT INTO boots VALUES(?,?,?,NULL)", (job, bank, str(claim.install_challenge))
            )
        return bank

    def close(self) -> None:
        self.db.close()

    def resolve(self, job: str, resolution: dict[str, object]) -> None:
        if (
            resolution.get("resolved") is not True
            or resolution.get("job_id") != job
            or resolution.get("device_id") != self.binding["device"]
        ):
            raise ValueError("No authoritative reconciliation for this claim")
        evidence = resolution["evidence"]
        if not isinstance(evidence, dict) or not isinstance(evidence.get("proof"), dict):
            raise ValueError("Observed bank evidence required")
        proof = evidence["proof"]
        active = self.active()
        if (
            not active
            or active["sha256"] != proof.get("sha256")
            or active["security_version"] != proof.get("security_version")
        ):
            raise ValueError("Local bank differs from reconciled observation")
        encoded = json.dumps(resolution, sort_keys=True)
        operation = "reconcile:" + job
        previous = self.db.execute(
            "SELECT payload FROM local_audit WHERE operation=?", (operation,)
        ).fetchone()
        if previous and previous[0] != encoded:
            raise ValueError("Conflicting local reconciliation")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO local_audit VALUES(?,?)", (operation, encoded))
            self.db.execute("UPDATE jobs SET state='reconciled' WHERE id=?", (job,))
            self.db.execute("UPDATE reports SET delivered=2 WHERE job_id=? AND delivered=0", (job,))

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
        if path.stat().st_size > self.max_artifact_bytes:
            raise ValueError("Oversized local bank")
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def image_quota(self, requested: int, job: str) -> None:
        import shutil

        images = self.root / "images"
        if images.is_symlink():
            raise ValueError("Unsafe image pool")
        stale = images / (job + ".part")
        if stale.is_symlink():
            raise ValueError("Unsafe stale staging path")
        if stale.exists():
            if stale.parent.resolve() != images.resolve():
                raise ValueError("Staging path escaped image directory")
            stale.unlink()
        keep = {
            str(row[0])
            for row in self.db.execute("SELECT sha256 FROM banks WHERE sha256 IS NOT NULL")
        }
        for row in self.db.execute(
            "SELECT claim FROM jobs WHERE claim IS NOT NULL "
            "AND (state IN "
            "('claimed','downloaded','installing') OR "
            "EXISTS(SELECT 1 FROM reports WHERE "
            "reports.job_id=jobs.id AND delivered=0))"
        ):
            keep.add(json.loads(row[0])["manifest"]["sha256"])
        size = 0
        if images.exists():
            for path in images.iterdir():
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.parent.resolve() != images.resolve()
                ):
                    raise ValueError("Unsafe bank pool entry")
                if (
                    path.suffix == ".bin"
                    and len(path.stem) == 64
                    and all(c in "0123456789abcdef" for c in path.stem)
                    and path.stem not in keep
                ):
                    path.unlink()
                else:
                    size += path.stat().st_size
        if (
            requested > self.max_artifact_bytes
            or size + requested > 3 * self.max_artifact_bytes
            or shutil.disk_usage(self.root).free < requested + 1024**2
        ):
            raise ValueError("Device staging/disk quota exceeded")

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
        active = self.active()
        if (
            active
            and claim.recorded_security_version is not None
            and (active["security_version"], active["version"])
            != (claim.recorded_security_version, claim.recorded_firmware_version)
            and (
                active["job_id"] != str(job.id)
                or (active["security_version"], active["version"])
                != (claim.manifest.security_version, claim.manifest.version)
            )
        ):
            raise ValueError(
                "Local observed bank disagrees with trusted cloud floor; reconcile before execution"
            )
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
                install_challenge=str(claim.install_challenge) if claim.install_challenge else None,
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
        proof: InstallationProof | None = None,
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
            installation_proof=proof,
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

    def activate(
        self, claim: ClaimResult, *, healthy: bool, proof: InstallationProof | None = None
    ) -> None:
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
                bank = self.stage(claim)
                if (
                    proof is None
                    or proof.challenge != claim.install_challenge
                    or proof.claim_token != claim.claim_token
                    or proof.job_id != claim.job.id
                    or proof.sha256 != manifest.sha256
                    or proof.security_version != manifest.security_version
                    or proof.bank != bank
                    or proof.device_id != self.binding["device"]
                ):
                    raise ValueError("Confirmed candidate boot proof required")
                count = int(str(previous["installations"])) + 1 if previous else 1
                self.db.execute(
                    "INSERT OR REPLACE INTO active VALUES (1,?,?,?,?,?,?)",
                    (
                        job,
                        manifest.sha256,
                        manifest.version,
                        manifest.security_version,
                        count,
                        bank,
                    ),
                )
                self.db.execute("UPDATE banks SET state='confirmed' WHERE name=?", (bank,))
                self.db.execute(
                    "UPDATE boots SET proof=? WHERE job_id=?", (proof.model_dump_json(), job)
                )
                self.enqueue(claim, "succeeded", proof=proof)
                self.db.execute("UPDATE jobs SET state='installed' WHERE id=?", (job,))
            else:
                self.db.execute(
                    "UPDATE banks SET state='failed' WHERE job_id=? AND state='pending_boot'",
                    (job,),
                )
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
