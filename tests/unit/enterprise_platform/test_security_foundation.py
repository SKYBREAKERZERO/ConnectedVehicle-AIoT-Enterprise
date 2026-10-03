from __future__ import annotations

import pytest

from enterprise_platform.security.authorization import (
    AuthenticationRequiredError,
    AuthorizationDeniedError,
    has_permission,
    require_permission,
    require_security_context,
    resolve_permissions,
)
from enterprise_platform.security.context import (
    SecurityContext,
    bind_security_context,
    get_security_context,
)
from enterprise_platform.security.identity import (
    Principal,
    PrincipalType,
    Role,
)
from enterprise_platform.security.permissions import (
    ALL_PERMISSIONS,
    Permission,
)


def test_principal_normalizes_identifiers() -> None:
    principal = Principal(
        principal_id="  user-123  ",
        principal_type=PrincipalType.USER,
        tenant_id="  tenant-456  ",
    )

    assert principal.principal_id == "user-123"
    assert principal.tenant_id == "tenant-456"


@pytest.mark.parametrize(
    "principal_id",
    [
        "",
        "   ",
    ],
)
def test_principal_rejects_empty_identifier(
    principal_id: str,
) -> None:
    with pytest.raises(ValueError):
        Principal(
            principal_id=principal_id,
            principal_type=PrincipalType.USER,
        )


def test_principal_rejects_empty_tenant_identifier() -> None:
    with pytest.raises(ValueError):
        Principal(
            principal_id="user-123",
            principal_type=PrincipalType.USER,
            tenant_id="   ",
        )


def test_security_context_binding_restores_previous_context() -> None:
    outer = SecurityContext(
        principal=Principal(
            principal_id="outer-user",
            principal_type=PrincipalType.USER,
        )
    )

    inner = SecurityContext(
        principal=Principal(
            principal_id="inner-service",
            principal_type=PrincipalType.SERVICE,
        )
    )

    assert get_security_context() is None

    with bind_security_context(outer):
        assert get_security_context() == outer

        with bind_security_context(inner):
            assert get_security_context() == inner

        assert get_security_context() == outer

    assert get_security_context() is None


def test_vehicle_owner_role_grants_vehicle_permissions() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="owner-001",
            principal_type=PrincipalType.USER,
            roles=frozenset({Role.VEHICLE_OWNER}),
        )
    )

    permissions = resolve_permissions(context)

    assert Permission.VEHICLE_READ in permissions
    assert Permission.VEHICLE_COMMAND in permissions
    assert Permission.OTA_MANAGE not in permissions


def test_direct_permission_is_added_to_role_permissions() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="service-001",
            principal_type=PrincipalType.SERVICE,
        ),
        granted_permissions=frozenset(
            {
                Permission.DEVICE_READ,
            }
        ),
    )

    assert has_permission(context, Permission.DEVICE_READ)
    assert not has_permission(context, Permission.DEVICE_MANAGE)


def test_platform_admin_receives_all_permissions() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="admin-001",
            principal_type=PrincipalType.USER,
            roles=frozenset({Role.PLATFORM_ADMIN}),
        )
    )

    assert resolve_permissions(context) == ALL_PERMISSIONS


def test_vehicle_device_can_publish_telemetry_but_not_manage_ota() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="device-001",
            principal_type=PrincipalType.DEVICE,
            roles=frozenset({Role.VEHICLE_DEVICE}),
        )
    )

    assert has_permission(
        context,
        Permission.TELEMETRY_PUBLISH,
    )
    assert not has_permission(
        context,
        Permission.OTA_MANAGE,
    )


def test_require_permission_allows_authorized_principal() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="owner-001",
            principal_type=PrincipalType.USER,
            roles=frozenset({Role.VEHICLE_OWNER}),
        )
    )

    require_permission(
        context,
        Permission.VEHICLE_COMMAND,
    )


def test_require_permission_raises_for_unauthorized_principal() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="device-001",
            principal_type=PrincipalType.DEVICE,
            roles=frozenset({Role.VEHICLE_DEVICE}),
        )
    )

    with pytest.raises(AuthorizationDeniedError) as exc_info:
        require_permission(
            context,
            Permission.OTA_MANAGE,
        )

    assert exc_info.value.permission is Permission.OTA_MANAGE


def test_require_security_context_returns_bound_context() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="user-001",
            principal_type=PrincipalType.USER,
        )
    )

    with bind_security_context(context):
        assert require_security_context() == context


def test_require_security_context_rejects_missing_authentication() -> None:
    with pytest.raises(AuthenticationRequiredError):
        require_security_context()
