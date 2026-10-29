"""Per-run signed LOCAL rehearsal credentials. Never a GitHub/OIDC/STS adapter.

Issuer/key and workers are trusted fixture infrastructure. Exported keys belong
only in private temporary fixture files, never in artifacts or deployment jobs.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import Any

from scripts.iac.plan_admission import canonical_digest

ROLES = {
    "publisher": {"register-state", "revoke-state"},
    "requester": {
        "request-recovery",
        "consume-recovery",
        "revalidate-recovery-receipt",
        "inspect-recovery-consumption",
    },
    "reviewer": {"approve-recovery", "revoke-recovery-approval"},
    "operator": {"operator-reconcile-resource"},
}


class LocalRehearsalIdentity:
    def __init__(self, key: bytes, *, endpoint: str, commit: str, run_id: str):
        if (
            len(key) != 32
            or re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint) is None
            or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        ):
            raise ValueError(
                "local issuer requires ephemeral loopback scope and a 32-byte fixture key"
            )
        self._key = key
        self.endpoint = endpoint
        self.commit = commit
        self.run_id = run_id
        self._active: ContextVar[str | None] = ContextVar("rehearsal_actor", default=None)
        self.revoked: set[str] = set()
        self.proofs: dict[str, dict[str, Any]] = {}
        self.tokens = {
            name: self.issue("principal", name, {"actions": sorted(actions)})
            for name, actions in ROLES.items()
        }

    def issue(self, kind: str, subject: str, payload: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        claims = {
            "issuer": "local-rehearsal",
            "audience": "day29-localstack-only",
            "account": "000000000000",
            "environment": "local",
            "endpoint": self.endpoint,
            "commit": self.commit,
            "run_id": self.run_id,
            "kind": kind,
            "subject": subject,
            "payload_sha256": canonical_digest(payload),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        }
        signature = hmac.new(
            self._key, canonical_digest(claims).encode(), hashlib.sha256
        ).hexdigest()
        return {"claims": claims, "signature": signature}

    def verify(
        self, token: dict[str, Any], kind: str, subject: str, payload: dict[str, Any]
    ) -> bool:
        try:
            if set(token) != {"claims", "signature"}:
                return False
            c = token["claims"]
            if set(c) != {
                "issuer",
                "audience",
                "account",
                "environment",
                "endpoint",
                "commit",
                "run_id",
                "kind",
                "subject",
                "payload_sha256",
                "issued_at",
                "expires_at",
            }:
                return False
            wanted = {
                "issuer": "local-rehearsal",
                "audience": "day29-localstack-only",
                "account": "000000000000",
                "environment": "local",
                "endpoint": self.endpoint,
                "commit": self.commit,
                "run_id": self.run_id,
                "kind": kind,
                "subject": subject,
                "payload_sha256": canonical_digest(payload),
            }
            if any(c.get(k) != v for k, v in wanted.items()) or subject in self.revoked:
                return False
            issued = datetime.fromisoformat(c["issued_at"])
            expires = datetime.fromisoformat(c["expires_at"])
            now = datetime.now(UTC)
            if (
                any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in (issued, expires))
                or not issued <= now < expires
                or not timedelta(0) < expires - issued <= timedelta(minutes=10)
            ):
                return False
            return hmac.compare_digest(
                token["signature"],
                hmac.new(self._key, canonical_digest(c).encode(), hashlib.sha256).hexdigest(),
            )
        except Exception:
            return False

    @contextmanager
    def session(self, actor: str) -> Iterator[None]:
        if actor not in ROLES or not self.verify(
            self.tokens[actor], "principal", actor, {"actions": sorted(ROLES[actor])}
        ):
            raise ValueError("invalid local principal credential")
        marker = self._active.set(actor)
        try:
            yield
        finally:
            self._active.reset(marker)

    def observe(self, kind: str, payload: dict[str, Any]) -> None:
        self.proofs[kind + ":" + canonical_digest(payload)] = self.issue(kind, "publisher", payload)

    def observed(self, kind: str, payload: dict[str, Any]) -> bool:
        token = self.proofs.get(kind + ":" + canonical_digest(payload))
        return token is not None and self.verify(token, kind, "publisher", payload)

    def authenticate(self, actor: str, action: str, digest: str) -> bool:
        if actor not in ROLES or not self.verify(
            self.tokens[actor], "principal", actor, {"actions": sorted(ROLES[actor])}
        ):
            return False
        if action == "honor-recovery-approval":
            token = self.proofs.get("review:" + digest)
            return token is not None and self.verify(token, "review", actor, {"digest": digest})
        if (
            self._active.get() != actor
            or action not in ROLES[actor]
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            return False
        if action == "register-state" and not self.observed(
            "state-read", {"record_sha256": digest}
        ):
            return False
        if action == "approve-recovery":
            self.proofs["review:" + digest] = self.issue("review", actor, {"digest": digest})
        return True

    def private_bundle(self) -> dict[str, Any]:
        return {
            "key": self._key.hex(),
            "endpoint": self.endpoint,
            "commit": self.commit,
            "run_id": self.run_id,
            "tokens": self.tokens,
            "proofs": self.proofs,
        }

    @classmethod
    def from_private_bundle(cls, value: dict[str, Any]) -> LocalRehearsalIdentity:
        result = cls(
            bytes.fromhex(value["key"]),
            endpoint=value["endpoint"],
            commit=value["commit"],
            run_id=value["run_id"],
        )
        result.tokens = value["tokens"]
        result.proofs = value["proofs"]
        return result
