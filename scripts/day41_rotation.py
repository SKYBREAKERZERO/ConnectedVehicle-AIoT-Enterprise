"""Fail-closed Staging rotation checkpoints. This module performs no cloud writes."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scripts.day37_preflight import REGION


class Phase(StrEnum):
    REQUESTED = "REQUESTED"
    PENDING_CREATED = "PENDING_CREATED"
    TARGET_UPDATED = "TARGET_UPDATED"
    PENDING_TESTED = "PENDING_TESTED"
    SECRET_PROMOTED = "SECRET_PROMOTED"
    CLIENTS_REFRESHED = "CLIENTS_REFRESHED"
    OLD_RETIRED = "OLD_RETIRED"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


SEQUENCE = tuple(Phase)[:-1]
CHECKS: dict[Phase, set[str]] = {
    Phase.PENDING_CREATED: {"pending_version_matches"},
    Phase.TARGET_UPDATED: {"target_version_matches"},
    Phase.PENDING_TESTED: {"new_tls_login"},
    Phase.SECRET_PROMOTED: {"current_version_matches"},
    Phase.CLIENTS_REFRESHED: {
        "all_tasks_replaced",
        "api",
        "tenant_isolation",
        "outbox",
        "remote_command",
        "ota",
    },
    Phase.OLD_RETIRED: {"new_tls_login", "old_login_rejected"},
    Phase.VERIFIED: {"continuity", "cloudwatch", "recovery_exercise"},
}


@dataclass(frozen=True)
class Scope:
    account: str
    region: str
    kind: str
    secret_arn: str
    version: str

    def __post_init__(self) -> None:
        paths = {"postgres": "database/application", "redis": "redis/auth"}
        if (
            not re.fullmatch(r"(?!0{12})[0-9]{12}", self.account)
            or self.region != REGION
            or self.kind not in paths
            or not re.fullmatch(r"[A-Za-z0-9-]{32,64}", self.version)
        ):
            raise ValueError("Invalid rotation scope")
        arn = f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:"
        path = "/connected-vehicle/staging/" + paths[self.kind]
        if not re.fullmatch(re.escape(arn + path) + r"-[A-Za-z0-9]{6}", self.secret_arn):
            raise ValueError("Secret outside the exact Staging scope")


class Journal:
    """Persist observations; a failed operation is never retried or rolled back here."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        scope: Scope,
        expected: Phase,
        target: Phase,
        observation_scope: Scope,
        checks: Mapping[str, bool],
        digest: str,
    ) -> None:
        if scope != observation_scope or not re.fullmatch(r"(?!0{64})[a-f0-9]{64}", digest):
            raise ValueError("Unbound observation")
        if expected in {Phase.BLOCKED, Phase.VERIFIED} or target == Phase.REQUESTED:
            raise ValueError("Terminal or invalid transition")
        required = set(CHECKS.get(target, set()))
        if scope.kind == "redis" and target == Phase.TARGET_UPDATED:
            required.add("old_and_new_tls_login")
        if scope.kind == "postgres" and target == Phase.PENDING_TESTED:
            required.add("rls_and_grants_unchanged")
        if target != Phase.BLOCKED and (
            SEQUENCE[SEQUENCE.index(expected) + 1] != target
            or set(checks) != required
            or any(value is not True for value in checks.values())
        ):
            raise ValueError("Missing or out-of-order rotation observation")
        if target == Phase.BLOCKED and checks:
            raise ValueError("Blocked checkpoints cannot contain success claims")
        with sqlite3.connect(self.path, timeout=2) as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS checkpoints (
                    account TEXT, region TEXT, secret TEXT, version TEXT,
                    phase TEXT, digest TEXT,
                    PRIMARY KEY (account, region, secret, version, phase)
                )"""
            )
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                """SELECT secret, version, phase, digest FROM checkpoints
                   WHERE account = ? AND region = ? ORDER BY rowid""",
                (scope.account, scope.region),
            ).fetchall()
            latest = {(secret, version): phase for secret, version, phase, _ in rows}
            own = (scope.secret_arn, scope.version)
            current = latest.get(own, Phase.REQUESTED)
            if current == target and (*own, target, digest) in rows:
                return
            if current != expected or any(
                key != own and phase != Phase.VERIFIED for key, phase in latest.items()
            ):
                raise ValueError("Stale checkpoint or unresolved Staging rotation")
            db.execute(
                "INSERT INTO checkpoints VALUES (?, ?, ?, ?, ?, ?)",
                (scope.account, scope.region, *own, target, digest),
            )
