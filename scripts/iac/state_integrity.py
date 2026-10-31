"""Read-only state/backup admission models. No state push, restore or unlock API."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from scripts.iac.plan_admission import canonical_digest

RECORD_FIELDS = {
    "account",
    "environment",
    "bucket",
    "key",
    "version_id",
    "sha256",
    "lineage",
    "serial",
    "commit",
    "run_id",
}
Authority = Callable[[dict[str, Any]], bool]


def validate_record(record: dict[str, Any]) -> None:
    """Validate record syntax only; authentication is a separate mandatory boundary."""
    if set(record) != RECORD_FIELDS:
        raise ValueError("closed trusted version record required")
    if (
        record["environment"] not in {"local", "production"}
        or re.fullmatch(r"[0-9]{12}", record["account"]) is None
        or (record["environment"] == "production" and record["account"] == "000000000000")
    ):
        raise ValueError("reviewed account/environment required")
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", record["bucket"]) is None
        or record["key"] != f"ota/{record['environment']}/terraform.tfstate"
    ):
        raise ValueError("reviewed backend path required")
    if (
        not isinstance(record["version_id"], str)
        or not record["version_id"].strip()
        or record["version_id"] == "null"
    ):
        raise ValueError("versioned backend required")
    if (
        type(record["serial"]) is not int
        or record["serial"] < 0
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", record["lineage"]) is None
    ):
        raise ValueError("valid lineage and serial required")
    if (
        re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        or re.fullmatch(r"[0-9a-f]{40}", record["commit"]) is None
        or (
            re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", record["run_id"]) is None
            and not (
                record["run_id"] == "local:1"
                and record["environment"] == "local"
                and record["account"] == "000000000000"
            )
        )
    ):
        raise ValueError("digest, commit and run attempt required")


def _reject_constant(_: str) -> Any:
    raise ValueError("nonfinite state JSON")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate state JSON key")
        result[key] = value
    return result


def state_errors(
    raw: bytes | None,
    *,
    observed: dict[str, Any],
    expected: dict[str, Any],
    authenticate: Authority,
) -> list[str]:
    """Version, serial and lineage must equal a separately authenticated record.

    The caller supplies observed backend identity from a trusted read context;
    a hash or arbitrary JSON metadata cannot establish S3 account ownership.
    """
    try:
        if type(raw) is not bytes or not raw or len(raw) > 20_000_000:
            raise ValueError("state missing, empty or oversized")
        if set(expected) != RECORD_FIELDS or set(observed) != RECORD_FIELDS:
            raise ValueError("closed trusted state-record schema required")
        validate_record(expected)
        if any(
            type(observed[k]) is not type(expected[k]) or observed[k] != expected[k]
            for k in RECORD_FIELDS
        ):
            raise ValueError("state version, scope or trusted record mismatch")
        if hashlib.sha256(raw).hexdigest() != expected["sha256"]:
            raise ValueError("state SHA-256 mismatch")
        state = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
        if (
            not isinstance(state, dict)
            or type(state.get("version")) is not int
            or state.get("version") != 4
            or type(state.get("serial")) is not int
            or state["serial"] < 0
            or not isinstance(state.get("outputs"), dict)
            or not isinstance(state.get("resources"), list)
        ):
            raise ValueError("invalid Terraform state structure")
        if (
            re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", state.get("lineage", ""))
            is None
            or type(expected["serial"]) is not int
            or state["lineage"] != expected["lineage"]
            or state["serial"] != expected["serial"]
        ):
            raise ValueError("state lineage or serial changed/rolled back")
        if authenticate(dict(expected)) is not True:
            raise ValueError("state record authority unavailable or rejected")
    except Exception as exc:
        return [str(exc) or type(exc).__name__]
    return []


def recovery_errors(
    *,
    record: dict[str, Any],
    active: dict[str, Any],
    target: dict[str, Any],
    approval: dict[str, Any],
    actor: str,
    now: datetime,
    lock_present: bool,
    authenticate: Authority,
) -> list[str]:
    """Admit only a simulated recovery copy into a distinct LOCAL disposable backend.

    This returns validation errors, never execution permission for production.
    """
    try:
        validate_record(record)
        if lock_present is not False:
            raise ValueError("lock requires separate manual reconciliation")
        if set(active) != {"account", "environment", "bucket", "key"} or set(target) != {
            "account",
            "environment",
            "bucket",
            "key",
            "disposable",
        }:
            raise ValueError("closed recovery backend schema required")
        if (
            target["disposable"] is not True
            or target["environment"] != "local"
            or target["account"] != "000000000000"
            or active["environment"] != "local"
            or active["account"] != "000000000000"
            or target["bucket"] == active["bucket"]
            or target["key"] != active["key"]
        ):
            raise ValueError("only a separate disposable LocalStack backend may be exercised")
        if any(record[k] != active[k] for k in active):
            raise ValueError("backup belongs to another backend")
        binding = canonical_digest({"record": record, "active": active, "target": target})
        if (
            set(approval)
            != {"binding_sha256", "reviewer", "approved_at", "expires_at", "recovery_id"}
            or approval["binding_sha256"] != binding
            or not approval["recovery_id"]
        ):
            raise ValueError("approval must bind exact source version, run and destination")
        if (
            re.fullmatch(r"[A-Za-z0-9-]{1,39}", actor) is None
            or re.fullmatch(r"[A-Za-z0-9-]{1,39}", approval["reviewer"]) is None
            or actor.casefold() == approval["reviewer"].casefold()
        ):
            raise ValueError("independent recovery review required")
        approved = datetime.fromisoformat(approval["approved_at"])
        expires = datetime.fromisoformat(approval["expires_at"])
        if (
            any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in (now, approved, expires))
            or not approved <= now < expires
            or not timedelta(0) < expires - approved <= timedelta(minutes=15)
        ):
            raise ValueError("recovery approval expired or unbounded")
        if authenticate(dict(approval)) is not True:
            raise ValueError("recovery approval revoked or unverified")
    except Exception as exc:
        return [str(exc) or type(exc).__name__]
    return []
