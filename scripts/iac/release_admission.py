"""Day27 persistent OFFLINE admission model. READY never grants AWS execution rights.

Trust callbacks must eventually be backed by an authenticated control plane.
This local SQLite demonstration cannot coordinate separate GitHub runners.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.iac.plan_admission import admission_errors, canonical_digest, plan_errors

Authority = Callable[[dict[str, Any]], bool]
TERMINAL = {"REJECTED", "INTERRUPTED"}


def evidence_errors(
    manifest: dict[str, Any], evidence: dict[str, Any], source: str, now: datetime, request_id: str
) -> list[str]:
    try:
        if set(evidence) != {
            "request_id",
            "manifest_sha256",
            "source_sha256",
            "run_id",
            "repository",
            "workflow",
            "conclusion",
            "created_at",
            "expires_at",
        }:
            raise ValueError("closed evidence schema required")
        if (
            evidence["request_id"] != request_id
            or evidence["manifest_sha256"] != canonical_digest(manifest)
            or evidence["source_sha256"] != source
            or re.fullmatch(r"[0-9a-f]{64}", source) is None
            or evidence["run_id"] != manifest["run_id"]
            or evidence["repository"] != "SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise"
            or evidence["workflow"] != ".github/workflows/ci.yml"
            or evidence["conclusion"] != "success"
        ):
            raise ValueError("evidence source, run, target or workflow mismatch")
        issued = datetime.fromisoformat(evidence["created_at"])
        expires = datetime.fromisoformat(evidence["expires_at"])
        if (
            any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in (now, issued, expires))
            or not datetime.fromisoformat(manifest["created_at"]) <= issued <= now < expires
            or not timedelta(0) < expires - issued <= timedelta(minutes=30)
        ):
            raise ValueError("evidence is stale or unbounded")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return [str(exc)]
    return []


class ReleaseStore:
    """Local durable model with atomic compare-and-transition and append-only events.

    No delete/unlock/retry/reset API: ambiguous interruptions keep reservations.
    Filesystem/database administrators are outside this model's trust boundary.
    """

    def __init__(self, path: Path, *, localstack_rehearsal: bool = False):
        self.path = path
        self.localstack_rehearsal = localstack_rehearsal
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS releases (
                    id TEXT PRIMARY KEY, binding TEXT NOT NULL, state TEXT NOT NULL,
                    approval TEXT, actor TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS spent (
                    plan_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS holders (
                    backend TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL,
                    state TEXT NOT NULL, detail TEXT NOT NULL
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=2)

    def request(
        self,
        request_id: str,
        manifest: dict[str, Any],
        evidence: dict[str, Any],
        source: str,
        actor: str,
    ) -> None:
        if re.fullmatch(r"[a-z0-9-]{1,64}", request_id) is None:
            raise ValueError("bounded request ID required")
        binding = json.dumps(
            {"manifest": manifest, "evidence": evidence, "source": source},
            sort_keys=True,
            allow_nan=False,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO releases VALUES (?, ?, 'REQUESTED', NULL, ?)",
                (request_id, binding, actor),
            )
            connection.execute(
                "INSERT INTO events(request_id,state,detail) VALUES (?, 'REQUESTED', 'created')",
                (request_id,),
            )

    def state(self, request_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM releases WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise ValueError("unknown request")
            return str(row[0])

    def advance(
        self,
        request_id: str,
        target: str,
        *,
        manifest: dict[str, Any],
        plan: bytes,
        expected: dict[str, Any],
        evidence: dict[str, Any],
        source: str,
        now: datetime,
        evidence_authority: Authority,
        approval: dict[str, Any] | None = None,
        approval_authority: Authority | None = None,
    ) -> None:
        """Every transition rechecks current trusted context, provenance and expiration."""
        manifest, expected, evidence, approval = deepcopy((manifest, expected, evidence, approval))
        reason = ""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT binding,state,approval,actor FROM releases WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise ValueError("unknown request")
            stored, state, previous_approval, actor = row
            binding = {"manifest": manifest, "evidence": evidence, "source": source}
            allowed = {"REQUESTED": "VERIFIED", "VERIFIED": "APPROVED", "APPROVED": "READY"}
            if state in TERMINAL or allowed.get(state) != target:
                raise ValueError("illegal transition; terminal/consumed requests cannot resume")
            try:
                if canonical_digest(json.loads(stored)) != canonical_digest(binding):
                    raise ValueError("request binding changed; new verification required")
                errors = plan_errors(
                    manifest,
                    plan=plan,
                    expected=expected,
                    now=now,
                    localstack_rehearsal=self.localstack_rehearsal,
                )
                errors += evidence_errors(manifest, evidence, source, now, request_id)
                if errors:
                    raise ValueError("; ".join(errors))
                if evidence_authority(deepcopy(evidence)) is not True:
                    raise ValueError("current evidence authentication/revocation check failed")
                if target in {"APPROVED", "READY"}:
                    if approval is None or approval_authority is None:
                        raise ValueError("fresh independent approval required")
                    if (
                        set(approval)
                        != {
                            "request_id",
                            "binding_sha256",
                            "reviewer",
                            "approved_at",
                            "expires_at",
                            "approval_id",
                        }
                        or approval["request_id"] != request_id
                        or approval["binding_sha256"] != canonical_digest(binding)
                    ):
                        raise ValueError(
                            "approval belongs to a different request, source or evidence"
                        )
                    if (
                        not isinstance(approval["approval_id"], str)
                        or not approval["approval_id"].strip()
                    ):
                        raise ValueError("approval identity required")
                    expires = datetime.fromisoformat(approval["expires_at"])
                    approved = datetime.fromisoformat(approval["approved_at"])
                    if (
                        expires.tzinfo is None
                        or expires.utcoffset() != timedelta(0)
                        or not datetime.fromisoformat(evidence["created_at"]) <= approved
                        or not now < expires
                        or not timedelta(0) < expires - approved <= timedelta(minutes=15)
                    ):
                        raise ValueError("approval expired or outside bounded lifetime")
                    receipt = {
                        "manifest_sha256": canonical_digest(manifest),
                        "reviewer": approval["reviewer"],
                        "approved_at": approval["approved_at"],
                    }
                    errors = admission_errors(
                        manifest,
                        plan=plan,
                        expected=expected,
                        approval=receipt,
                        actor=actor,
                        now=now,
                        localstack_rehearsal=self.localstack_rehearsal,
                    )
                    if errors:
                        raise ValueError("; ".join(errors))
                    if approval_authority(deepcopy(approval)) is not True:
                        raise ValueError("approval revoked or not authenticated")
                    if target == "READY" and previous_approval != json.dumps(
                        approval, sort_keys=True
                    ):
                        raise ValueError("approval changed since APPROVED")
                if target == "READY":
                    backend = canonical_digest(
                        {
                            k: manifest[k]
                            for k in ("account", "state_bucket", "state_key", "state_region")
                        }
                    )
                    plan_id = canonical_digest(
                        {
                            k: manifest[k]
                            for k in (
                                "account",
                                "state_bucket",
                                "state_key",
                                "state_lineage",
                                "state_serial",
                                "plan_sha256",
                            )
                        }
                    )
                    # Both inserts roll back if either uniqueness check fails.
                    connection.execute("SAVEPOINT ready_reservation")
                    try:
                        connection.execute("INSERT INTO spent VALUES (?, ?)", (plan_id, request_id))
                        connection.execute(
                            "INSERT INTO holders VALUES (?, ?)", (backend, request_id)
                        )
                    except sqlite3.IntegrityError as exc:
                        connection.execute("ROLLBACK TO ready_reservation")
                        raise ValueError("plan spent or backend already reserved") from exc
                connection.execute(
                    "UPDATE releases SET state=?, approval=? WHERE id=?",
                    (
                        target,
                        json.dumps(approval, sort_keys=True) if approval else None,
                        request_id,
                    ),
                )
                connection.execute(
                    "INSERT INTO events(request_id,state,detail) "
                    "VALUES (?, ?, 'offline checks passed')",
                    (request_id, target),
                )
            except Exception as exc:
                # Persist denial before raising; callback/network faults also fail closed.
                reason = str(exc) or type(exc).__name__
                connection.execute("UPDATE releases SET state='REJECTED' WHERE id=?", (request_id,))
                connection.execute(
                    "INSERT INTO events(request_id,state,detail) VALUES (?, 'REJECTED', ?)",
                    (request_id, type(exc).__name__),
                )
        if reason:
            raise ValueError(reason)

    def interrupt(self, request_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM releases WHERE id=?", (request_id,)
            ).fetchone()
            if row is None or row[0] != "READY":
                raise ValueError("only READY can be interrupted")
            connection.execute("UPDATE releases SET state='INTERRUPTED' WHERE id=?", (request_id,))
            connection.execute(
                "INSERT INTO events(request_id,state,detail) "
                "VALUES (?, 'INTERRUPTED', 'reservation retained; manual review required')",
                (request_id,),
            )
