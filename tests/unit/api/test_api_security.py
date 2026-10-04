from __future__ import annotations

import pytest

from apps.api.security import get_remote_command_security_context
from enterprise_platform.security.context import (
    SecurityContext,
    bind_security_context,
)
from enterprise_platform.security.exceptions import (
    AuthenticationRequiredError,
    AuthorizationDeniedError,
)
from enterprise_platform.security.identity import (
    Principal,
    PrincipalType,
    Role,
)


def test_remote_command_security_requires_authentication() -> None:
    with pytest.raises(AuthenticationRequiredError):
        get_remote_command_security_context()


def test_remote_command_security_accepts_vehicle_owner_with_tenant() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="user-001",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-001",
            roles=frozenset(
                {
                    Role.VEHICLE_OWNER,
                }
            ),
        )
    )

    with bind_security_context(context):
        actual = get_remote_command_security_context()

    assert actual is context
    assert actual.principal.tenant_id == "tenant-001"


def test_remote_command_security_rejects_missing_permission() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="user-002",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-001",
        )
    )

    with bind_security_context(context), pytest.raises(AuthorizationDeniedError):
        get_remote_command_security_context()


def test_remote_command_security_rejects_tenantless_principal() -> None:
    context = SecurityContext(
        principal=Principal(
            principal_id="admin-001",
            principal_type=PrincipalType.USER,
            roles=frozenset(
                {
                    Role.PLATFORM_ADMIN,
                }
            ),
        )
    )

    with bind_security_context(context), pytest.raises(AuthorizationDeniedError):
        get_remote_command_security_context()
