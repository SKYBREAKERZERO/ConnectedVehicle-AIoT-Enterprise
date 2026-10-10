from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PrincipalType(StrEnum):
    """Supported caller identity categories."""

    USER = "user"
    SERVICE = "service"
    DEVICE = "device"


class Role(StrEnum):
    """Stable platform-level roles.

    Domain-specific authorization can evolve without changing the
    representation of the authenticated principal.
    """

    VEHICLE_OWNER = "vehicle_owner"
    FLEET_OPERATOR = "fleet_operator"
    OTA_OPERATOR = "ota_operator"

    VEHICLE_DEVICE = "vehicle_device"
    SYSTEM_SERVICE = "system_service"
    PLATFORM_ADMIN = "platform_admin"


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity presented to the application."""

    principal_id: str
    principal_type: PrincipalType
    tenant_id: str | None = None
    roles: frozenset[Role] = frozenset()
    device_vehicle_id: str | None = None

    def __post_init__(self) -> None:
        principal_id = self.principal_id.strip()

        if not principal_id:
            raise ValueError("Principal ID must not be empty.")

        object.__setattr__(self, "principal_id", principal_id)

        if self.tenant_id is None:
            return

        tenant_id = self.tenant_id.strip()

        if not tenant_id:
            raise ValueError("Tenant ID must not be empty when provided.")

        object.__setattr__(self, "tenant_id", tenant_id)
