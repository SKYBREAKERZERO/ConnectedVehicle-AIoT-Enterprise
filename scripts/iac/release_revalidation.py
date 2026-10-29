"""Day29 fresh release verification after a locally approved recovery.

Returns VERIFIED only. No method advances APPROVED/READY, restores state or Apply.
Registry, approval and Day27 release tables must share one isolated SQLite DB.
"""

from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from typing import Any

from scripts.iac.drift_policy import drift_report
from scripts.iac.plan_admission import canonical_digest, plan_errors
from scripts.iac.recovery_approval import RecoveryApprovals
from scripts.iac.release_admission import Authority, ReleaseStore
from scripts.iac.trusted_state_registry import (
    Clock,
    TrustedStateRegistry,
    governance_db,
    identifier,
    identity,
    utc,
)


def _trusted(authority: Authority, payload: dict[str, Any]) -> bool:
    try:
        return authority(deepcopy(payload)) is True
    except Exception:
        return False


def observation_binding(
    release_id: str,
    *,
    receipt: dict[str, Any],
    record: dict[str, Any],
    manifest: dict[str, Any],
    expected: dict[str, Any],
    evidence: dict[str, Any],
    source: str,
    refresh_code: int,
    refresh_plan: dict[str, Any],
    normal_code: int,
    normal_plan: dict[str, Any],
) -> dict[str, Any]:
    return {
        "release_id": release_id,
        "receipt_sha256": receipt["receipt_sha256"],
        "state_record_sha256": canonical_digest(record),
        "manifest_sha256": canonical_digest(manifest),
        "expected_sha256": canonical_digest(expected),
        "source_sha256": source,
        "evidence_sha256": canonical_digest(evidence),
        "refresh_exit": refresh_code,
        "refresh_plan_sha256": canonical_digest(refresh_plan),
        "normal_exit": normal_code,
        "normal_plan_sha256": canonical_digest(normal_plan),
        "drift": drift_report(refresh_code, refresh_plan, normal_code, normal_plan),
    }


class ReleaseRevalidator:
    def __init__(
        self,
        path: Path,
        *,
        registry: TrustedStateRegistry,
        approvals: RecoveryApprovals,
        evidence_authority: Authority,
        observation_authority: Authority,
        clock: Clock,
        localstack_rehearsal: bool = False,
    ):
        self.path = path.resolve()
        if self.path != registry.path or self.path != approvals.path:
            raise ValueError("all governance components must share one transaction database")
        self.registry, self.approvals = registry, approvals
        if localstack_rehearsal != approvals.localstack_rehearsal or (
            localstack_rehearsal
            and (
                registry.scope["account"] != "000000000000"
                or registry.scope["environment"] != "local"
            )
        ):
            raise ValueError("explicit rehearsal mode must agree with the scoped approval service")
        self.localstack_rehearsal = localstack_rehearsal
        self._evidence_authority, self._observation_authority = (
            evidence_authority,
            observation_authority,
        )
        self._clock = clock
        self.releases = ReleaseStore(self.path, localstack_rehearsal=localstack_rehearsal)
        with governance_db(self.path) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS day29_revalidations (
                release_id TEXT PRIMARY KEY, receipt_sha256 TEXT UNIQUE NOT NULL,
                binding TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL
            )""")
            connection.commit()

    def _check(
        self,
        *,
        receipt: dict[str, Any],
        actor: str,
        record: dict[str, Any],
        raw: bytes,
        manifest: dict[str, Any],
        plan: bytes,
        expected: dict[str, Any],
        drift: dict[str, Any],
    ) -> dict[str, Any]:
        request = self.approvals.validate_consumed(receipt, actor=actor)
        self.registry.verify(raw, record)
        if self.registry.scope != request["target"]:
            raise ValueError("registered recovered state belongs to another target")
        original = request["source_record"]
        if any(
            record[k] != original[k]
            for k in ("account", "environment", "sha256", "lineage", "serial")
        ):
            raise ValueError(
                "recovered bytes/lineage/serial differ from the approved source version"
            )
        fields = {
            "account": "account",
            "environment": "environment",
            "bucket": "state_bucket",
            "key": "state_key",
            "lineage": "state_lineage",
            "serial": "state_serial",
            "commit": "commit",
            "run_id": "run_id",
        }
        if any(
            type(record[k]) is not type(manifest[v]) or record[k] != manifest[v]
            for k, v in fields.items()
        ):
            raise ValueError("fresh release is not bound to the registered recovered state")
        if manifest["plan_sha256"] == request["previous_plan_sha256"] or (
            not self.localstack_rehearsal and manifest["run_id"] == request["previous_run_id"]
        ):
            raise ValueError("old plan or production run cannot be reused")
        from datetime import datetime

        if datetime.fromisoformat(manifest["created_at"]) < datetime.fromisoformat(
            receipt["consumed_at"]
        ):
            raise ValueError("new plan must be produced after recovery approval consumption")
        errors = plan_errors(
            manifest,
            plan=plan,
            expected=expected,
            now=utc(self._clock),
            localstack_rehearsal=self.localstack_rehearsal,
        )
        if errors:
            raise ValueError("; ".join(errors))
        if (
            drift.get("decision") != "CLEAR"
            or drift.get("state_drift") is not False
            or drift.get("configuration_drift") is not False
        ):
            raise ValueError("drift/error prohibits release verification")
        return request

    def verify(
        self,
        release_id: str,
        *,
        receipt: dict[str, Any],
        actor: str,
        raw: bytes,
        record: dict[str, Any],
        manifest: dict[str, Any],
        plan: bytes,
        expected: dict[str, Any],
        evidence: dict[str, Any],
        source: str,
        refresh_code: int,
        refresh_plan: dict[str, Any],
        normal_code: int,
        normal_plan: dict[str, Any],
    ) -> dict[str, Any]:
        release_id, actor = identifier(release_id), identity(actor)
        receipt, record, manifest, expected, evidence, refresh_plan, normal_plan = deepcopy(
            (receipt, record, manifest, expected, evidence, refresh_plan, normal_plan)
        )
        if type(raw) is not bytes or type(plan) is not bytes:
            raise ValueError("immutable state/plan bytes required")
        drift = drift_report(refresh_code, refresh_plan, normal_code, normal_plan)
        args: dict[str, Any] = {
            "receipt": receipt,
            "actor": actor,
            "record": record,
            "raw": raw,
            "manifest": manifest,
            "plan": plan,
            "expected": expected,
            "drift": drift,
        }
        request = self._check(**args)
        if release_id == request["previous_release_id"]:
            raise ValueError("interrupted/rejected request cannot be resumed")
        observation = observation_binding(
            release_id,
            receipt=receipt,
            record=record,
            manifest=manifest,
            expected=expected,
            evidence=evidence,
            source=source,
            refresh_code=refresh_code,
            refresh_plan=refresh_plan,
            normal_code=normal_code,
            normal_plan=normal_plan,
        )
        if not _trusted(self._observation_authority, observation):
            raise ValueError("current state/plan/drift observation is not authenticated")
        with governance_db(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._check(**args)
            if connection.execute("SELECT 1 FROM releases WHERE id=?", (release_id,)).fetchone():
                raise ValueError("a fresh Day27 request ID is required")
            try:
                connection.execute(
                    "INSERT INTO day29_revalidations VALUES (?,?,?,?,'CLAIMED')",
                    (
                        release_id,
                        receipt["receipt_sha256"],
                        json.dumps(observation, sort_keys=True),
                        canonical_digest(observation),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("recovery receipt/revalidation ID already claimed") from exc
            connection.commit()

        def admit(current_evidence: dict[str, Any]) -> bool:
            # Called inside Day27's BEGIN IMMEDIATE: same-DB registry/revocation
            # writers cannot race the final observation check and VERIFIED write.
            self._check(**args)
            with governance_db(self.path) as connection:
                row = connection.execute(
                    "SELECT binding,digest,status FROM day29_revalidations WHERE release_id=?",
                    (release_id,),
                ).fetchone()
                if (
                    row is None
                    or row[2] != "CLAIMED"
                    or canonical_digest(json.loads(row[0])) != row[1]
                    or row[1] != canonical_digest(observation)
                ):
                    return False
            return _trusted(self._evidence_authority, current_evidence) and _trusted(
                self._observation_authority, observation
            )

        try:
            self.releases.request(release_id, manifest, evidence, source, actor)
            self.releases.advance(
                release_id,
                "VERIFIED",
                manifest=manifest,
                plan=plan,
                expected=expected,
                evidence=evidence,
                source=source,
                now=utc(self._clock),
                evidence_authority=admit,
            )
        except Exception:
            with governance_db(self.path) as connection:
                connection.execute(
                    "UPDATE day29_revalidations SET status='REJECTED' WHERE release_id=?",
                    (release_id,),
                )
                connection.commit()
            raise
        with governance_db(self.path) as connection:
            connection.execute(
                "UPDATE day29_revalidations SET status='VERIFIED' WHERE release_id=?", (release_id,)
            )
            connection.execute(
                "INSERT INTO day29_audit(subject,action,actor,detail) VALUES (?,'REVALIDATE',?,?)",
                (release_id, actor, canonical_digest(observation)),
            )
            connection.commit()
        return {
            "status": "VERIFIED",
            "release_id": release_id,
            "binding_sha256": canonical_digest(observation),
            "apply_authorized": False,
            "new_release_approval_required": True,
            "production_identity_verified": False,
            "cross_runner_coordination_verified": False,
        }
