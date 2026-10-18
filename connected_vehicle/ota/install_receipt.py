"""Short-lived installation capabilities, independent of application DB passwords."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

from connected_vehicle.ota.artifacts import unique_pairs


def load_key(path: Path, tenant: str) -> tuple[str, bytes]:
    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized receipt key registry")
    item = json.loads(data, object_pairs_hook=unique_pairs)[tenant]
    key = base64.b64decode(item["secret"], validate=True)
    if len(key) != 32 or not isinstance(item["key_id"], str) or not item["key_id"]:
        raise ValueError("Invalid receipt key")
    return item["key_id"], key


def sign_receipt(path: Path, tenant: str, **values: Any) -> tuple[str, str]:
    key_id, key = load_key(path, tenant)
    payload = json.dumps(
        dict(
            protocol="cv-install/1",
            tenant_id=tenant,
            key_id=key_id,
            expires=int(time.time()) + 60,
            **values,
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return payload, hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
