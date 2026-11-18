"""Local Day30 isolation ledger. No restore, promotion, approval reset or Apply."""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.iac.plan_admission import canonical_digest

DAY30_TABLES = {"day30_quarantine", "day30_audit"}


class Quarantined(ValueError):
    pass


class CandidateConflict(ValueError):
    pass


class IsolationUnavailable(ValueError):
    """No safe result is known. Caller must query operation_id, never retry adoption."""


def tables(c: sqlite3.Connection) -> set[str]:
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def not_quarantined(c: sqlite3.Connection, release_id: str) -> None:
    if "day30_quarantine" in tables(c):
        row = c.execute(
            "SELECT status FROM day30_quarantine WHERE release_id=?", (release_id,)
        ).fetchone()
        # RECONCILED is historical acknowledgement, never permission to reuse an ID.
        if row is not None:
            raise Quarantined("QUARANTINED: release ID permanently retired from admission")


def _record_current(c: sqlite3.Connection, digest: str) -> bool:
    row = c.execute(
        "SELECT backend,version_id,record,digest,status FROM day29_versions WHERE digest=?",
        (digest,),
    ).fetchone()
    if row is None or row[4] != "ACTIVE":
        return False
    record = json.loads(row[2])
    scope = {k: record[k] for k in ("account", "environment", "bucket", "key")}
    head = c.execute(
        "SELECT version_id,lineage,serial FROM day29_heads WHERE backend=?", (row[0],)
    ).fetchone()
    return bool(
        canonical_digest(scope) == row[0]
        and canonical_digest(record) == digest == row[3]
        and head == (row[1], record["lineage"], record["serial"])
    )


def observation(c: sqlite3.Connection, release_id: str, now: datetime) -> dict[str, Any]:
    """Read durable bindings in the caller's transaction. No mutations or callbacks."""
    names = tables(c)
    d27 = (
        c.execute("SELECT state,binding FROM releases WHERE id=?", (release_id,)).fetchone()
        if "releases" in names
        else None
    )
    d29 = (
        c.execute(
            "SELECT receipt_sha256,binding,digest,status FROM day29_revalidations "
            "WHERE release_id=?",
            (release_id,),
        ).fetchone()
        if "day29_revalidations" in names
        else None
    )
    result: dict[str, Any] = {
        "release_id": release_id,
        "receipt_sha256": "",
        "day27_state": "ABSENT" if d27 is None else d27[0],
        "day29_state": "ABSENT" if d29 is None else d29[3],
        "reason_code": None,
        "binding_sha256": "",
    }
    if d29 is None:
        return result
    result.update(receipt_sha256=d29[0], binding_sha256=d29[2])
    if d29[3] == "CLAIMED":
        result["reason_code"] = "PARTIAL_COMMIT"
    elif d29[3] == "REJECTED":
        result["reason_code"] = "REVALIDATION_REJECTED"
    elif d29[3] != "VERIFIED" or d27 is None or d27[0] not in {"VERIFIED", "APPROVED", "READY"}:
        result["reason_code"] = "STATE_INCONSISTENT"
    try:
        binding = json.loads(d29[1])
        if canonical_digest(binding) != d29[2] or binding["receipt_sha256"] != d29[0]:
            raise ValueError("binding changed")
        receipt_row = c.execute(
            "SELECT approval_id,payload,digest FROM day29_consumptions WHERE digest=?", (d29[0],)
        ).fetchone()
        if receipt_row is None:
            raise ValueError("missing receipt")
        receipt = json.loads(receipt_row[1])
        if (
            canonical_digest(receipt) != d29[0]
            or receipt["approval"]["approval_id"] != receipt_row[0]
        ):
            raise ValueError("receipt changed")
        a = c.execute(
            "SELECT status,digest,payload,request_id FROM day29_approvals WHERE id=?",
            (receipt_row[0],),
        ).fetchone()
        if a is None or a[0] != "CONSUMED":
            result["reason_code"] = "APPROVAL_REVOKED"
        else:
            token = json.loads(a[2])
            request = receipt["request"]
            req = c.execute(
                "SELECT status,digest,payload FROM day29_recovery_requests WHERE id=?", (a[3],)
            ).fetchone()
            if (
                canonical_digest(token) != a[1]
                or receipt["approval"] != {**token, "approval_sha256": a[1]}
                or req is None
                or req[0] != "CONSUMED"
                or canonical_digest(request) != req[1]
                or json.loads(req[2]) != request
                or token["request_sha256"] != req[1]
            ):
                raise ValueError("approval/request binding changed")
            if (
                not datetime.fromisoformat(token["approved_at"])
                <= now
                < datetime.fromisoformat(token["expires_at"])
            ):
                result["reason_code"] = "APPROVAL_EXPIRED"
        if not _record_current(
            c, canonical_digest(receipt["request"]["source_record"])
        ) or not _record_current(c, binding["state_record_sha256"]):
            result["reason_code"] = "STATE_HEAD_CHANGED"
        if d27 is not None:
            payload = json.loads(d27[1])
            if (
                canonical_digest(payload["manifest"]) != binding["manifest_sha256"]
                or canonical_digest(payload["evidence"]) != binding["evidence_sha256"]
                or payload["source"] != binding["source_sha256"]
            ):
                result["reason_code"] = "RELEASE_BINDING_CHANGED"
    except (KeyError, TypeError, ValueError):
        result["reason_code"] = "CORRUPT_BINDING"
    return result


def admissible(c: sqlite3.Connection, release_id: str, now: datetime) -> None:
    not_quarantined(c, release_id)
    current = observation(c, release_id, now)
    reason = current["reason_code"]
    # The in-flight REQUESTED -> VERIFIED write is checked by Day29's trusted
    # callback under this same lock. After that write, CLAIMED is never admissible.
    if reason == "PARTIAL_COMMIT" and current["day27_state"] in {"ABSENT", "REQUESTED"}:
        return
    if reason is not None:
        raise Quarantined("QUARANTINED: " + reason + "; read-only reconciliation required")


def _commit(c: sqlite3.Connection) -> None:
    c.commit()


def acquire(c: sqlite3.Connection, operation: str) -> None:
    for attempt in range(3):
        try:
            c.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            if attempt == 2:
                raise IsolationUnavailable(
                    "bounded lock wait; inspect operation_id=" + operation
                ) from exc
            time.sleep(0.02 * (attempt + 1))


class QuarantineStore:
    def __init__(
        self, path: Path, *, clock: Callable[[], datetime] | None = None, initialize: bool = True
    ):
        self.path = path.resolve()
        self.clock = clock or (lambda: datetime.now(UTC))
        with closing(self._connect(readonly=not initialize)) as c:
            row = c.execute("SELECT value FROM day29_meta WHERE name='purpose'").fetchone()
            if row != ("iac-governance-offline-v1",):
                raise ValueError("dedicated initialized governance DB required")
            if not initialize:
                return
            c.executescript("""
                CREATE TABLE IF NOT EXISTS day30_quarantine (
                    quarantine_id TEXT PRIMARY KEY, release_id TEXT NOT NULL UNIQUE,
                    receipt_sha256 TEXT NOT NULL, reason_code TEXT NOT NULL,
                    observed_day27_state TEXT NOT NULL, observed_day29_state TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL, status TEXT NOT NULL
                        CHECK(status IN ('ACTIVE','RECONCILED')),
                    created_at TEXT NOT NULL, reconciled_at TEXT
                );
                CREATE TABLE IF NOT EXISTS day30_audit (
                    sequence INTEGER PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
                    release_id TEXT NOT NULL, action TEXT NOT NULL, evidence_sha256 TEXT NOT NULL
                );
            """)

    def _connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        c = sqlite3.connect(
            self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=0.05
        )
        return c

    def scan(self) -> list[dict[str, Any]]:
        """Read only, including at the SQLite connection. CLAIMED may be in flight."""
        with closing(self._connect(readonly=True)) as c:
            c.execute("BEGIN")
            if "day29_revalidations" not in tables(c):
                return []
            return [
                observation(c, r[0], self.clock())
                for r in c.execute("SELECT release_id FROM day29_revalidations ORDER BY release_id")
            ]

    def lookup(self, operation_id: str) -> dict[str, Any] | None:
        with closing(self._connect(readonly=True)) as c:
            row = c.execute(
                "SELECT quarantine_id,release_id,reason_code,status FROM day30_quarantine "
                "WHERE quarantine_id=?",
                (operation_id,),
            ).fetchone()
            return (
                None
                if row is None
                else dict(
                    zip(("operation_id", "release_id", "reason_code", "status"), row, strict=True)
                )
            )

    def quarantine(
        self, release_id: str, *, candidate: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Explicit trusted operator/owner call, not an unauthenticated network API.

        Retry only BEGIN acquisition. Never retry writes/commit. Unknown commit
        result is resolved by reopening and looking up the stable operation ID.
        """
        operation = canonical_digest({"action": "quarantine", "release_id": release_id})
        c = self._connect()
        try:
            acquire(c, operation)
            prior = c.execute(
                "SELECT quarantine_id FROM day30_quarantine WHERE release_id=?", (release_id,)
            ).fetchone()
            if prior is None:
                obs = observation(c, release_id, self.clock())
                if candidate is not None:
                    if set(candidate) != {"receipt_sha256", "binding_sha256", "reason_code"}:
                        raise ValueError("closed owner-candidate binding required")
                    # Rejected preflight can reserve only a new, authenticated owner's ID.
                    if obs["day27_state"] != "ABSENT" or obs["day29_state"] != "ABSENT":
                        raise CandidateConflict("candidate cannot isolate an existing request")
                    if c.execute(
                        "SELECT 1 FROM day29_revalidations WHERE receipt_sha256=?",
                        (candidate["receipt_sha256"],),
                    ).fetchone():
                        raise CandidateConflict(
                            "losing competitor cannot quarantine a winning receipt"
                        )
                    obs.update(candidate)
                if obs["reason_code"] is None:
                    raise ValueError("no durable inconsistency; no quarantine")
                digest = canonical_digest(obs)
                c.execute(
                    "INSERT INTO day30_quarantine VALUES (?,?,?,?,?,?,?,'ACTIVE',?,NULL)",
                    (
                        operation,
                        release_id,
                        obs["receipt_sha256"],
                        obs["reason_code"],
                        obs["day27_state"],
                        obs["day29_state"],
                        digest,
                        self.clock().isoformat(),
                    ),
                )
                c.execute(
                    "INSERT INTO day30_audit(operation_id,release_id,action,evidence_sha256) "
                    "VALUES (?,?,'QUARANTINE',?)",
                    (operation, release_id, digest),
                )
            try:
                _commit(c)
            except sqlite3.Error as exc:
                c.close()
                try:
                    recovered = self.lookup(operation)
                except sqlite3.Error:
                    recovered = None
                if recovered is None:
                    raise IsolationUnavailable(
                        "unknown commit; inspect operation_id=" + operation
                    ) from exc
                return recovered
        finally:
            c.close()
        result = self.lookup(operation)
        if result is None:
            raise IsolationUnavailable("unknown commit; inspect operation_id=" + operation)
        return result

    def acknowledge(self, operation_id: str) -> dict[str, Any]:
        """Trusted operator acknowledges classification, never clears an admission block."""
        with closing(self._connect()) as c:
            acquire(c, operation_id)
            row = c.execute(
                "SELECT release_id,evidence_sha256,status FROM day30_quarantine "
                "WHERE quarantine_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise ValueError("unknown quarantine operation")
            if row[2] == "ACTIVE":
                c.execute(
                    "UPDATE day30_quarantine SET status='RECONCILED',reconciled_at=? "
                    "WHERE quarantine_id=?",
                    (self.clock().isoformat(), operation_id),
                )
                c.execute(
                    "INSERT INTO day30_audit(operation_id,release_id,action,evidence_sha256) "
                    "VALUES (?,?,'ACKNOWLEDGE',?)",
                    (operation_id + ":ack", row[0], row[1]),
                )
            try:
                _commit(c)
            except sqlite3.Error as exc:
                c.close()
                result = self.lookup(operation_id)
                if result is None or result["status"] != "RECONCILED":
                    raise IsolationUnavailable(
                        "unknown acknowledgement; inspect operation_id=" + operation_id
                    ) from exc
                return result
        result = self.lookup(operation_id)
        if result is None:
            raise IsolationUnavailable("missing acknowledgement operation")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--quarantine", metavar="RELEASE_ID")
    actions.add_argument("--acknowledge", metavar="OPERATION_ID")
    args = parser.parse_args()
    store = QuarantineStore(args.database, initialize=bool(args.quarantine or args.acknowledge))
    result: Any = (
        store.quarantine(args.quarantine)
        if args.quarantine
        else store.acknowledge(args.acknowledge)
        if args.acknowledge
        else store.scan()
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
