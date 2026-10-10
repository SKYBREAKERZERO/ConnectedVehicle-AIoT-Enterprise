from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

import jwt
from jwt import PyJWKClient
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from enterprise_platform.config.settings import Settings
from enterprise_platform.security.context import SecurityContext, bind_security_context
from enterprise_platform.security.identity import Principal, PrincipalType
from enterprise_platform.security.permissions import Permission


class OIDCVerifier:
    """Trust only configured RS256 keys, issuer, audience and signed identity claims."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.keys = (
            PyJWKClient(
                settings.oidc_jwks_url,
                timeout=settings.oidc_timeout_seconds,
                cache_keys=False,
                max_cached_keys=16,
                lifespan=300,
            )
            if settings.oidc_jwks_url
            else None
        )
        self.public_key = (
            Path(settings.oidc_public_key_file).read_text()
            if settings.oidc_public_key_file
            else None
        )
        self.capacity = asyncio.Semaphore(4)

    def verify(self, token: str) -> SecurityContext:
        if len(token) > 16384:
            raise jwt.InvalidTokenError("Token too large")
        key = self.keys.get_signing_key_from_jwt(token).key if self.keys else self.public_key
        if key is None:
            raise jwt.InvalidTokenError("No trusted signing key")
        cognito = self.settings.oidc_token_profile == "cognito"
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=self.settings.oidc_issuer,
            audience=self.settings.oidc_audience,
            leeway=5,
            options={"require": ["exp", "iat", "iss", "sub"], "verify_aud": not cognito},
        )
        if cognito and (
            claims.get("token_use") != "access"
            or claims.get("client_id") != self.settings.oidc_audience
        ):
            raise jwt.InvalidTokenError("Invalid Cognito access token")
        if claims.get("token_use", "access") != "access":
            raise jwt.InvalidTokenError("ID tokens are not API access tokens")
        tenant = claims.get(self.settings.oidc_tenant_claim)
        subject = claims.get("sub")
        scope = claims.get("scope", "")
        if (
            not isinstance(tenant, str)
            or not tenant.strip()
            or tenant != tenant.strip()
            or len(tenant) > 255
            or not isinstance(subject, str)
            or not isinstance(scope, str)
        ):
            raise jwt.InvalidTokenError("Missing signed identity claims")
        try:
            kind = PrincipalType(claims.get("principal_type", "user"))
            vehicle = str(UUID(claims["vehicle_id"])) if kind is PrincipalType.DEVICE else None
        except (ValueError, KeyError, TypeError) as exc:
            raise jwt.InvalidTokenError("Invalid device identity") from exc
        allowed = {
            p for p in Permission if self.settings.oidc_scope_prefix + p.value in scope.split()
        }
        if kind is PrincipalType.DEVICE:
            allowed &= {Permission.TELEMETRY_PUBLISH, Permission.COMMAND_REPORT}
        return SecurityContext(
            Principal(subject, kind, tenant_id=tenant, device_vehicle_id=vehicle),
            granted_permissions=frozenset(allowed),
        )

    async def authenticate(self, token: str) -> SecurityContext | None:
        async with self.capacity:
            try:
                return await asyncio.to_thread(self.verify, token)
            except (jwt.PyJWTError, OSError, ValueError):
                return None


class OIDCMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.verifier = OIDCVerifier(settings) if settings.oidc_issuer else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.verifier:
            scheme, _, token = Headers(scope=scope).get("authorization", "").partition(" ")
            if scheme.lower() == "bearer" and token:
                context = await self.verifier.authenticate(token)
                if context is not None:
                    with bind_security_context(context):
                        await self.app(scope, receive, send)
                    return
        await self.app(scope, receive, send)
