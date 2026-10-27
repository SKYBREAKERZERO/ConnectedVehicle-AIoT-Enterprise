"""Day26 offline saved-plan contracts. No AWS calls, approval authority or Apply path.

Expected context/approval must eventually come from an authenticated control plane,
not from the manifest author. SQLite below only demonstrates atomic replay claims;
it is NOT a cross-run production deployment ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

FIELDS = {
    "commit",
    "run_id",
    "environment",
    "account",
    "plan_role",
    "apply_role",
    "state_bucket",
    "state_key",
    "state_region",
    "state_kms_key_arn",
    "state_lineage",
    "state_serial",
    "lockfile_sha256",
    "terraform_version",
    "plan_sha256",
    "created_at",
    "expires_at",
}
BOUND = FIELDS - {"plan_sha256", "created_at", "expires_at"}
TTL = timedelta(minutes=30)


def canonical_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def plan_errors(
    manifest: dict[str, Any],
    *,
    plan: bytes,
    expected: dict[str, Any],
    now: datetime,
) -> list[str]:
    """Validate an offline model; success does not authorize a production deployment."""
    try:
        if set(manifest) != FIELDS or set(expected) != BOUND:
            raise ValueError("exact manifest and trusted context schemas required")
        if any(
            type(manifest[k]) is not type(expected[k]) or manifest[k] != expected[k] for k in BOUND
        ):
            raise ValueError("plan differs from trusted release/state context")
        if re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]) is None:
            raise ValueError("full commit required")
        if re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", manifest["run_id"]) is None:
            raise ValueError("run ID and attempt required")
        if (
            manifest["environment"] != "production"
            or re.fullmatch(r"[0-9]{12}", manifest["account"]) is None
            or manifest["account"] == "000000000000"
        ):
            raise ValueError("production account/environment required")
        roles = [manifest["plan_role"], manifest["apply_role"]]
        if roles[0] == roles[1] or any(
            re.fullmatch(rf"arn:aws:iam::{manifest['account']}:role/[A-Za-z0-9+=,.@_/-]+", role)
            is None
            for role in roles
        ):
            raise ValueError("distinct account-bound plan and apply roles required")
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", manifest["state_bucket"]) is None
            or manifest["state_key"] != "ota/production/terraform.tfstate"
        ):
            raise ValueError("reviewed state target required")
        if (
            manifest["state_region"] != "ap-northeast-1"
            or re.fullmatch(
                rf"arn:aws:kms:ap-northeast-1:{manifest['account']}:key/[0-9a-f-]{{36}}",
                manifest["state_kms_key_arn"],
            )
            is None
        ):
            raise ValueError("reviewed backend region and account-owned KMS key required")
        if (
            re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                manifest["state_lineage"],
            )
            is None
            or type(manifest["state_serial"]) is not int
            or manifest["state_serial"] < 0
        ):
            raise ValueError("current state lineage and serial required")
        if (
            manifest["terraform_version"] != "1.14.7"
            or re.fullmatch(r"[0-9a-f]{64}", manifest["lockfile_sha256"]) is None
        ):
            raise ValueError("reviewed Terraform and provider lock required")
        if not plan or manifest["plan_sha256"] != hashlib.sha256(plan).hexdigest():
            raise ValueError("saved plan bytes differ or are empty")
        created = datetime.fromisoformat(manifest["created_at"])
        expires = datetime.fromisoformat(manifest["expires_at"])
        if (
            any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in (created, expires, now))
            or not created <= now < expires
            or not timedelta(0) < expires - created <= TTL
        ):
            raise ValueError("plan expired, future-dated or outside bounded UTC lifetime")
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        return [str(exc)]
    return []


def admission_errors(
    manifest: dict[str, Any],
    *,
    plan: bytes,
    expected: dict[str, Any],
    approval: dict[str, Any],
    actor: str,
    now: datetime,
) -> list[str]:
    errors = plan_errors(manifest, plan=plan, expected=expected, now=now)
    if errors:
        return errors
    try:
        created = datetime.fromisoformat(manifest["created_at"])
        if set(approval) != {"manifest_sha256", "reviewer", "approved_at"} or approval[
            "manifest_sha256"
        ] != canonical_digest(manifest):
            raise ValueError("approval must bind the complete manifest")
        reviewed = datetime.fromisoformat(approval["approved_at"])
        if (
            reviewed.tzinfo is None
            or reviewed.utcoffset() != timedelta(0)
            or not created <= reviewed <= now
        ):
            raise ValueError("approval is not current")
        login = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
        if (
            re.fullmatch(login, actor) is None
            or re.fullmatch(login, approval["reviewer"]) is None
            or approval["reviewer"].casefold() == actor.casefold()
        ):
            raise ValueError("independent authenticated reviewer required")
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        return [str(exc)]
    return []


def reserve_offline_once(ledger: Path, manifest: dict[str, Any]) -> None:
    """Atomic fail-closed local demonstration. A failed/crashed reservation stays spent.

    Rebuilding a production plan would require new review and a centrally durable
    authenticated ledger. Never use this machine-local database as that authority.
    """
    # Exclude timestamps and run labels: relabeling an identical plan cannot evade replay.
    key = canonical_digest(
        {
            k: manifest[k]
            for k in (
                "account",
                "environment",
                "state_bucket",
                "state_key",
                "state_lineage",
                "state_serial",
                "plan_sha256",
            )
        }
    )
    with sqlite3.connect(ledger, timeout=1) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS reservations "
            "(plan_id TEXT PRIMARY KEY, manifest TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO reservations VALUES (?, ?)", (key, canonical_digest(manifest))
        )


def ruleset_errors(ruleset: dict[str, Any]) -> list[str]:
    try:
        if (
            ruleset["target"] != "branch"
            or ruleset["enforcement"] != "active"
            or ruleset["bypass_actors"] != []
            or ruleset["conditions"]
            != {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
        ):
            raise ValueError("main must have active rules with no bypass")
        reviews = [r["parameters"] for r in ruleset["rules"] if r["type"] == "pull_request"]
        checks = [
            r["parameters"] for r in ruleset["rules"] if r["type"] == "required_status_checks"
        ]
        if (
            len(reviews) != 1
            or type(reviews[0]["required_approving_review_count"]) is not int
            or reviews[0]["required_approving_review_count"] < 1
            or any(
                reviews[0].get(k) is not True
                for k in (
                    "dismiss_stale_reviews_on_push",
                    "require_last_push_approval",
                    "required_review_thread_resolution",
                )
            )
        ):
            raise ValueError("independent, fresh, last-push approval required")
        if (
            len(checks) != 1
            or checks[0]["strict_required_status_checks_policy"] is not True
            or checks[0].get("do_not_enforce_on_create") is not False
            or {(c["context"], c["integration_id"]) for c in checks[0]["required_status_checks"]}
            != {("IaC quality gate", 15368), ("Runtime quality gate", 15368)}
        ):
            raise ValueError("strict Runtime and IaC checks required")
        if not {"deletion", "non_fast_forward"} <= {r["type"] for r in ruleset["rules"]}:
            raise ValueError("deletion and force-push protection required")
    except (KeyError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []
