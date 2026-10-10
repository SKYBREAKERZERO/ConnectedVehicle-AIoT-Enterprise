from __future__ import annotations

import secrets

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from enterprise_platform.config.settings import Settings
from enterprise_platform.security.context import SecurityContext, bind_security_context
from enterprise_platform.security.identity import Principal, PrincipalType
from enterprise_platform.security.permissions import Permission


class ServiceTokenMiddleware:
    """Optional, explicitly provisioned single-tenant service identity.

    Never infer identity/tenant/permissions from caller headers. With no token
    configured, the existing trusted authentication integration is required.
    Deploy behind TLS; this is a service credential, not an end-user login.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.token = settings.api_service_token
        self.tenant = settings.api_service_tenant_id

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.token and self.tenant:
            authorization = Headers(scope=scope).get("authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() == "bearer" and secrets.compare_digest(
                token.encode(), self.token.get_secret_value().encode()
            ):
                context = SecurityContext(
                    principal=Principal(
                        "command-service", PrincipalType.SERVICE, tenant_id=self.tenant
                    ),
                    granted_permissions=frozenset({Permission.VEHICLE_COMMAND}),
                )
                with bind_security_context(context):
                    await self.app(scope, receive, send)
                return
        await self.app(scope, receive, send)
