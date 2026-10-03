from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from enterprise_platform.security.context import (
    SecurityContext,
    get_security_context,
)
from enterprise_platform.security.identity import Role
from enterprise_platform.security.permissions import (
    ALL_PERMISSIONS,
    Permission,
)

ROLE_PERMISSIONS: Final[Mapping[Role, frozenset[Permission]]] = {
    Role.VEHICLE_OWNER: frozenset(
        {
            Permission.VEHICLE_READ,
            Permission.VEHICLE_COMMAND,
        }
    ),
    Role.FLEET_OPERATOR: frozenset(
        {
            Permission.VEHICLE_READ,
            Permission.VEHICLE_COMMAND,
            Permission.DEVICE_READ,
        }
    ),
    Role.OTA_OPERATOR: frozenset(
        {
            Permission.VEHICLE_READ,
            Permission.DEVICE_READ,
            Permission.OTA_READ,
            Permission.OTA_MANAGE,
        }
    ),
    Role.VEHICLE_DEVICE: frozenset(
        {
            Permission.TELEMETRY_PUBLISH,
        }
    ),
    Role.SYSTEM_SERVICE: ALL_PERMISSIONS,
    Role.PLATFORM_ADMIN: ALL_PERMISSIONS,
}


class AuthenticationRequiredError(Exception):
    """Raised when an operation requires an authenticated principal."""

    def __init__(self) -> None:
        super().__init__("Authentication is required.")


class AuthorizationDeniedError(Exception):
    """Raised when a principal lacks a required permission."""

    def __init__(self, permission: Permission) -> None:
        self.permission = permission

        super().__init__(f"Permission '{permission.value}' is required.")


def resolve_permissions(
    context: SecurityContext,
) -> frozenset[Permission]:
    permissions = set(context.granted_permissions)

    for role in context.principal.roles:
        permissions.update(
            ROLE_PERMISSIONS.get(
                role,
                frozenset(),
            )
        )

    return frozenset(permissions)


def has_permission(
    context: SecurityContext,
    permission: Permission,
) -> bool:
    return permission in resolve_permissions(context)


def require_security_context() -> SecurityContext:
    context = get_security_context()

    if context is None:
        raise AuthenticationRequiredError()

    return context


def require_permission(
    context: SecurityContext,
    permission: Permission,
) -> None:
    if has_permission(
        context,
        permission,
    ):
        return

    raise AuthorizationDeniedError(permission)
