from __future__ import annotations

from enterprise_platform.security.authorization import (
    require_permission,
    require_security_context,
)
from enterprise_platform.security.context import SecurityContext
from enterprise_platform.security.exceptions import AuthorizationDeniedError
from enterprise_platform.security.permissions import Permission


def get_remote_command_security_context() -> SecurityContext:
    context = require_security_context()

    require_permission(
        context,
        Permission.VEHICLE_COMMAND,
    )

    if context.principal.tenant_id is None:
        raise AuthorizationDeniedError(
            Permission.VEHICLE_COMMAND,
        )

    return context
