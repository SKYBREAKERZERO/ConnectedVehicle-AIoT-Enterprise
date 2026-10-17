"""Versioned publisher trust records; legacy key maps require explicit migration."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def records(path: Path, tenant: str) -> dict[str, Any]:
    from connected_vehicle.ota.artifacts import unique_pairs

    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized publisher registry")
    document = json.loads(data, object_pairs_hook=unique_pairs)
    if document.get("protocol") != "cv-ota-keys/1":
        raise ValueError("Legacy publisher registry requires explicit migration")
    result = document["tenants"][tenant]
    for key, item in result.items():
        start, end = (datetime.fromisoformat(item[name]) for name in ("not_before", "not_after"))
        if (
            not key
            or len(base64.b64decode(item["public_key"], validate=True)) != 32
            or type(item["revoked"]) is not bool
            or start.utcoffset() is None
            or end.utcoffset() is None
            or end <= start
        ):
            raise ValueError("Invalid publisher lifecycle record")
    return dict(result)


def public_key(path: Path, tenant: str, key: str) -> bytes:
    item = records(path, tenant)[key]
    now = datetime.now(UTC)
    if item["revoked"] or not datetime.fromisoformat(
        item["not_before"]
    ) <= now < datetime.fromisoformat(item["not_after"]):
        raise ValueError("Publisher key revoked or outside validity period")
    return base64.b64decode(item["public_key"], validate=True)
