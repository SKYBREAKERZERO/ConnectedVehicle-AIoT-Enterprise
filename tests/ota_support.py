from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any


def registry(tenant: str, key: str, public: bytes) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "protocol": "cv-ota-keys/1",
        "tenants": {
            tenant: {
                key: {
                    "public_key": base64.b64encode(public).decode(),
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                    "revoked": False,
                }
            }
        },
    }
