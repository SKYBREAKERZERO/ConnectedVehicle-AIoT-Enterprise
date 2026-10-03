from __future__ import annotations

from enum import StrEnum
from typing import Final


class Permission(StrEnum):
    """Stable authorization capabilities used by application services."""

    VEHICLE_READ = "vehicle:read"
    VEHICLE_COMMAND = "vehicle:command"

    DEVICE_READ = "device:read"
    DEVICE_MANAGE = "device:manage"

    TELEMETRY_PUBLISH = "telemetry:publish"

    OTA_READ = "ota:read"
    OTA_MANAGE = "ota:manage"


ALL_PERMISSIONS: Final[frozenset[Permission]] = frozenset(Permission)
