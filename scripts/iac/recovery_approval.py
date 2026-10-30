"""Day29 request-bound local recovery approvals, atomically consumed once.

No method performs recovery, unlock, state writes or AWS Apply. Authentication
adapters are service bootstrap dependencies, never supplied by a token holder.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.iac.failure_isolation import not_quarantined, tables
from scripts.iac.plan_admission import canonical_digest
from scripts.iac.release_admission import ReleaseStore
from scripts.iac.trusted_state_registry import (
    Authenticator,
    Clock,
    TrustedStateRegistry,
    authenticated,
    backend,
    governance_db,
    identifier,
    identity,
    utc,
)


class RecoveryApprovals:
    def __init__(
        self,
        path: Path,
        *,
        registry: TrustedStateRegistry,
        targets: tuple[dict[str, Any], ...],
        requesters: frozenset[str],
        reviewers: frozenset[str],
        authenticate: Authenticator,
        clock: Clock,
        localstack_rehearsal: bool = False,
    ):
        self.path = path.resolve()
        if self.path != registry.path:
            raise ValueError("registry and approvals must share the governance DB")
        self.registry, self._authenticate, self._clock = registry, authenticate, clock
        self.localstack_rehearsal = localstack_rehearsal
        if localstack_rehearsal and (
            registry.scope["account"] != "000000000000" or registry.scope["environment"] != "local"
        ):
            raise ValueError("rehearsal mode is confined to LocalStack scope")
        self._requesters = frozenset(identity(v) for v in requesters)
        self._reviewers = frozenset(identity(v) for v in reviewers)
        self._targets = frozenset(json.dumps(backend(deepcopy(t)), sort_keys=True) for t in targets)
        if not self._requesters or not self._reviewers or not self._targets:
            raise ValueError("explicit approval bootstrap policy required")
        for value in self._targets:
            target = json.loads(value)
            if (
                any(target[k] != registry.scope[k] for k in ("account", "environment", "key"))
                or target["bucket"] == registry.scope["bucket"]
            ):
                raise ValueError(
                    "recovery targets must be separate exact backends "
                    "in the same account/environment"
                )
        ReleaseStore(self.path, localstack_rehearsal=localstack_rehearsal, clock=clock)
        config = canonical_digest(
            {
                "source": registry.scope,
                "localstack_rehearsal": localstack_rehearsal,
                "targets": sorted(self._targets),
                "requesters": sorted(self._requesters),
                "reviewers": sorted(self._reviewers),
            }
        )
        with governance_db(self.path) as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS day29_recovery_requests (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL,
                    status TEXT NOT NULL, authority TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS day29_approvals (
                    id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES day29_recovery_requests(id)
                );
                CREATE TABLE IF NOT EXISTS day29_consumptions (
                    approval_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    digest TEXT UNIQUE NOT NULL,
                    FOREIGN KEY(approval_id) REFERENCES day29_approvals(id)
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            name = "approval-policy:" + registry.scope_id
            previous = connection.execute(
                "SELECT value FROM day29_meta WHERE name=?", (name,)
            ).fetchone()
            if previous is not None and previous[0] != config:
                raise ValueError("approval bootstrap policy changed")
            connection.execute("INSERT OR IGNORE INTO day29_meta VALUES (?,?)", (name, config))
            connection.commit()

    def _request(
        self, connection: Any, request_id: str, now: datetime
    ) -> tuple[dict[str, Any], str]:
        row = connection.execute(
            "SELECT payload,digest,status,authority FROM day29_recovery_requests WHERE id=?",
            (request_id,),
        ).fetchone()
        if row is None or row[3] != self.registry.scope_id:
            raise ValueError("unknown recovery request")
        value = json.loads(row[0])
        not_quarantined(connection, value["previous_release_id"])
        if canonical_digest(value) != row[1]:
            raise ValueError("recovery request was substituted")
        if (
            not datetime.fromisoformat(value["requested_at"])
            <= now
            < datetime.fromisoformat(value["expires_at"])
        ):
            raise ValueError("recovery request expired or clock regressed")
        if not self.registry.is_current(value["source_record"]):
            raise ValueError("source version superseded, revoked or unregistered")
        origin = connection.execute(
            "SELECT binding,state FROM releases WHERE id=?", (value["previous_release_id"],)
        ).fetchone()
        if (
            origin is None
            or origin[1] not in {"INTERRUPTED", "REJECTED"}
            or canonical_digest(json.loads(origin[0])) != value["previous_binding_sha256"]
        ):
            raise ValueError("origin release no longer matches interrupted/rejected context")
        return value, str(row[2])

    def request(
        self,
        request_id: str,
        *,
        record: dict[str, Any],
        target: dict[str, Any],
        previous_release_id: str,
        actor: str,
    ) -> dict[str, Any]:
        record, target = deepcopy((record, target))
        request_id, previous_release_id = identifier(request_id), identifier(previous_release_id)
        actor = identity(actor)
        if actor not in self._requesters:
            raise ValueError("requester not authorized")
        target = backend(target)
        if json.dumps(target, sort_keys=True) not in self._targets:
            raise ValueError("target backend not authorized")
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            not_quarantined(connection, previous_release_id)
            if not self.registry.is_current(record):
                raise ValueError("trusted active source version required")
            origin = connection.execute(
                "SELECT binding,state FROM releases WHERE id=?", (previous_release_id,)
            ).fetchone()
            if origin is None or origin[1] not in {"INTERRUPTED", "REJECTED"}:
                raise ValueError("origin must be an interrupted/rejected Day27 release")
            binding = json.loads(origin[0])
            manifest = binding["manifest"]
            association = {
                "account": "account",
                "environment": "environment",
                "bucket": "state_bucket",
                "key": "state_key",
                "lineage": "state_lineage",
                "serial": "state_serial",
                "commit": "commit",
                "run_id": "run_id",
            }
            if any(record[k] != manifest[v] for k, v in association.items()):
                raise ValueError("registered source does not match origin release")
            now = utc(self._clock)
            value = {
                "request_id": request_id,
                "source_record": record,
                "target": target,
                "previous_release_id": previous_release_id,
                "previous_binding_sha256": canonical_digest(binding),
                "previous_plan_sha256": manifest["plan_sha256"],
                "previous_commit": manifest["commit"],
                "previous_run_id": manifest["run_id"],
                "requester": actor,
                "requested_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=30)).isoformat(),
            }
            authenticated(self._authenticate, actor, "request-recovery", canonical_digest(value))
            connection.execute(
                "INSERT INTO day29_recovery_requests VALUES (?,?,?,'PENDING',?)",
                (
                    request_id,
                    json.dumps(value, sort_keys=True),
                    canonical_digest(value),
                    self.registry.scope_id,
                ),
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) "
                "VALUES (?,'REQUEST_RECOVERY',?,?)",
                (request_id, actor, canonical_digest(value)),
            )
            connection.commit()
        return deepcopy(value)

    def approve(
        self,
        request_id: str,
        approval_id: str,
        *,
        reviewer: str,
        lifetime: timedelta = timedelta(minutes=5),
    ) -> dict[str, Any]:
        request_id, approval_id = identifier(request_id), identifier(approval_id)
        reviewer = identity(reviewer)
        if reviewer not in self._reviewers:
            raise ValueError("reviewer not authorized")
        if not timedelta(0) < lifetime <= timedelta(minutes=15):
            raise ValueError("bounded approval lifetime required")
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = utc(self._clock)
            request, status = self._request(connection, request_id, now)
            if status != "PENDING" or reviewer == request["requester"]:
                raise ValueError("independent approval for a pending request required")
            expires = min(now + lifetime, datetime.fromisoformat(request["expires_at"]))
            token = {
                "approval_id": approval_id,
                "request_id": request_id,
                "request_sha256": canonical_digest(request),
                "reviewer": reviewer,
                "approved_at": now.isoformat(),
                "expires_at": expires.isoformat(),
            }
            authenticated(self._authenticate, reviewer, "approve-recovery", canonical_digest(token))
            connection.execute(
                "INSERT INTO day29_approvals VALUES (?,?,?,?,'ACTIVE')",
                (
                    approval_id,
                    request_id,
                    json.dumps(token, sort_keys=True),
                    canonical_digest(token),
                ),
            )
            connection.execute(
                "UPDATE day29_recovery_requests SET status='APPROVED' WHERE id=?", (request_id,)
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) "
                "VALUES (?,'APPROVE_RECOVERY',?,?)",
                (request_id, reviewer, canonical_digest(token)),
            )
            connection.commit()
        return {**token, "approval_sha256": canonical_digest(token)}

    def _approval(
        self, connection: Any, envelope: dict[str, Any], now: datetime, required: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = connection.execute(
            "SELECT payload,digest,status,request_id FROM day29_approvals WHERE id=?",
            (envelope.get("approval_id"),),
        ).fetchone()
        if row is None:
            raise ValueError("unknown approval")
        token = json.loads(row[0])
        if (
            canonical_digest(token) != row[1]
            or envelope != {**token, "approval_sha256": row[1]}
            or row[2] != required
        ):
            raise ValueError("approval substituted, revoked or already consumed")
        request, status = self._request(connection, row[3], now)
        if (
            canonical_digest(request) != token["request_sha256"]
            or status != {"ACTIVE": "APPROVED", "CONSUMED": "CONSUMED"}[required]
        ):
            raise ValueError("request approval binding changed")
        if token["reviewer"] == request["requester"] or token["reviewer"] not in self._reviewers:
            raise ValueError("independent reviewer required")
        if (
            not datetime.fromisoformat(token["approved_at"])
            <= now
            < datetime.fromisoformat(token["expires_at"])
        ):
            raise ValueError("approval expired or clock regressed")
        authenticated(self._authenticate, token["reviewer"], "honor-recovery-approval", row[1])
        return token, request

    def consume(self, envelope: dict[str, Any], *, actor: str) -> dict[str, Any]:
        envelope = deepcopy(envelope)
        actor = identity(actor)
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = utc(self._clock)
            token, request = self._approval(connection, envelope, now, "ACTIVE")
            if actor != request["requester"] or actor not in self._requesters:
                raise ValueError("only the authenticated requester may consume")
            authenticated(
                self._authenticate, actor, "consume-recovery", envelope["approval_sha256"]
            )
            receipt = {
                "approval": envelope,
                "request": request,
                "consumer": actor,
                "consumed_at": now.isoformat(),
            }
            digest = canonical_digest(receipt)
            connection.execute(
                "INSERT INTO day29_consumptions VALUES (?,?,?)",
                (token["approval_id"], json.dumps(receipt, sort_keys=True), digest),
            )
            changed = connection.execute(
                "UPDATE day29_approvals SET status='CONSUMED' WHERE id=? AND status='ACTIVE'",
                (token["approval_id"],),
            ).rowcount
            if changed != 1:
                raise ValueError("approval race lost")
            connection.execute(
                "UPDATE day29_recovery_requests SET status='CONSUMED' WHERE id=?",
                (token["request_id"],),
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) "
                "VALUES (?,'CONSUME_RECOVERY',?,?)",
                (token["request_id"], actor, digest),
            )
            connection.commit()
        return {**receipt, "receipt_sha256": digest}

    def validate_consumed(self, receipt: dict[str, Any], *, actor: str) -> dict[str, Any]:
        receipt = deepcopy(receipt)
        actor = identity(actor)
        with governance_db(self.path) as connection:
            row = connection.execute(
                "SELECT payload,digest FROM day29_consumptions WHERE approval_id=?",
                (receipt.get("approval", {}).get("approval_id"),),
            ).fetchone()
            if row is None:
                raise ValueError("approval was never consumed")
            value = json.loads(row[0])
            if (
                canonical_digest(value) != row[1]
                or receipt != {**value, "receipt_sha256": row[1]}
                or actor != value["consumer"]
            ):
                raise ValueError("consumption receipt substituted or belongs to another actor")
            if "day29_revalidations" in tables(connection):
                for linked in connection.execute(
                    "SELECT release_id FROM day29_revalidations WHERE receipt_sha256=?", (row[1],)
                ):
                    not_quarantined(connection, linked[0])
            _, request = self._approval(connection, value["approval"], utc(self._clock), "CONSUMED")
            authenticated(self._authenticate, actor, "revalidate-recovery-receipt", row[1])
            return deepcopy(request)

    def revoke(self, approval_id: str, *, reviewer: str) -> None:
        reviewer = identity(reviewer)
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload,request_id FROM day29_approvals WHERE id=?",
                (identifier(approval_id),),
            ).fetchone()
            if row is None or reviewer not in self._reviewers:
                raise ValueError("unknown or unauthorized approval")
            token = json.loads(row[0])
            if token["reviewer"] != reviewer:
                raise ValueError("only the issuing reviewer may revoke")
            authenticated(
                self._authenticate, reviewer, "revoke-recovery-approval", canonical_digest(token)
            )
            connection.execute(
                "UPDATE day29_approvals SET status='REVOKED' WHERE id=?", (approval_id,)
            )
            connection.execute(
                "UPDATE day29_recovery_requests SET status='REVOKED' WHERE id=?", (row[1],)
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) "
                "VALUES (?,'REVOKE_APPROVAL',?,?)",
                (row[1], reviewer, canonical_digest(token)),
            )
            connection.commit()

    def recover_consumed(self, envelope: dict[str, Any], *, actor: str) -> dict[str, Any]:
        """Read-only retrieval after a committed response was lost; never consume again."""
        envelope = deepcopy(envelope)
        actor = identity(actor)
        with governance_db(self.path) as connection:
            row = connection.execute(
                "SELECT payload,digest FROM day29_consumptions WHERE approval_id=?",
                (envelope.get("approval_id"),),
            ).fetchone()
            if row is None:
                raise ValueError("no committed consumption exists")
            value = json.loads(row[0])
            if value.get("approval") != envelope:
                raise ValueError("approval envelope mismatch")
            authenticated(self._authenticate, actor, "inspect-recovery-consumption", row[1])
            receipt = {**value, "receipt_sha256": row[1]}
        self.validate_consumed(receipt, actor=actor)
        return receipt
