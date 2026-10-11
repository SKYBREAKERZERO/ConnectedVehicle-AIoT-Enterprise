from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise_platform.security.context import get_security_context
from enterprise_platform.security.exceptions import AuthorizationDeniedError
from enterprise_platform.security.permissions import Permission


async def set_tenant_scope(session: AsyncSession, tenant: str) -> None:
    if (
        not tenant
        or tenant != tenant.strip()
        or len(tenant) > 255
        or any(ord(c) < 32 for c in tenant)
    ):
        raise ValueError("invalid_database_tenant_scope")
    identity = get_security_context()
    if identity is not None and identity.principal.tenant_id != tenant:
        raise AuthorizationDeniedError(Permission.VEHICLE_READ)
    # Transaction-local: no tenant identity survives commit/rollback or pool reuse.
    await session.execute(
        text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": tenant}
    )
