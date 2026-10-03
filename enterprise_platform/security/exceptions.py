from __future__ import annotations

from enterprise_platform.errors.base import ApplicationError
from enterprise_platform.errors.codes import ErrorCode
from enterprise_platform.security.permissions import Permission


class AuthenticationRequiredError(ApplicationError):
    """Raised when an operation requires an authenticated principal."""

    def __init__(
        self,
        message: str = "Authentication is required.",
    ) -> None:
        super().__init__(
            code=ErrorCode.AUTHENTICATION_REQUIRED,
            message=message,
        )


class AuthorizationDeniedError(ApplicationError):
    """Raised when a principal lacks a required permission."""

    def __init__(
        self,
        permission: Permission,
        message: str = "The principal is not authorized to perform this action.",
    ) -> None:
        self.permission = permission

        super().__init__(
            code=ErrorCode.AUTHORIZATION_DENIED,
            message=message,
        )
