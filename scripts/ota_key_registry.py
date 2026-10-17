"""Explicit legacy public-key-map conversion. Does not activate trust or re-sign artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from connected_vehicle.ota.artifacts import unique_pairs


def migrate(
    source: Path,
    output: Path,
    audit: Path,
    *,
    not_before: str,
    not_after: str,
    operation: str,
    actor: str,
    reason: str,
) -> None:
    UUID(operation)
    start, end = datetime.fromisoformat(not_before), datetime.fromisoformat(not_after)
    if (
        start.utcoffset() is None
        or end.utcoffset() is None
        or end <= start
        or not actor.strip()
        or not reason.strip()
    ):
        raise ValueError("Explicit validity window, operator and reason required")
    paths = [path.resolve() for path in (source, output, audit)]
    if (
        len(set(paths)) != 3
        or output.exists()
        or audit.exists()
        or output.is_symlink()
        or audit.is_symlink()
    ):
        raise FileExistsError("Conversion never replaces source, registry or audit files")
    with source.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Oversized legacy registry")
    old = json.loads(raw, object_pairs_hook=unique_pairs)
    if "protocol" in old:
        raise ValueError("Input is not a legacy key map")
    tenants: dict[str, Any] = {}
    for tenant, keys in old.items():
        tenants[tenant] = {}
        for key, public in keys.items():
            if len(base64.b64decode(public, validate=True)) != 32:
                raise ValueError("Invalid legacy Ed25519 public key")
            tenants[tenant][key] = dict(
                public_key=public, not_before=not_before, not_after=not_after, revoked=False
            )
    encoded = (
        json.dumps(dict(protocol="cv-ota-keys/1", tenants=tenants), sort_keys=True, indent=2) + "\n"
    ).encode()
    evidence = dict(
        operation=operation,
        actor=actor,
        reason=reason,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        registry_sha256=hashlib.sha256(encoded).hexdigest(),
        activated=False,
        artifacts_resigned=False,
    )
    # Both are exclusive outputs. An interrupted conversion never changes active trust.
    with audit.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2)
    with output.open("xb") as stream:
        stream.write(encoded)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "output", "audit"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("not-before", "not-after", "operation", "actor", "reason"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    migrate(
        args.input,
        args.output,
        args.audit,
        not_before=args.not_before,
        not_after=args.not_after,
        operation=args.operation,
        actor=args.actor,
        reason=args.reason,
    )
