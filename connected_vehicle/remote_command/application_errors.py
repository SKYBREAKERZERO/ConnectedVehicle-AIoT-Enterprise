from __future__ import annotations

from enterprise_platform.errors.base import ApplicationError
from enterprise_platform.errors.codes import ErrorCode


class RemoteCommandApplicationError(ApplicationError):
    """Base error for remote-command application use cases."""


class RemoteCommandVehicleNotFoundError(RemoteCommandApplicationError):
    """Vehicle is not visible in the caller tenant scope."""

    def __init__(
        self,
        message: str = "Vehicle was not found in the tenant scope.",
    ) -> None:
        super().__init__(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message,
        )


class RemoteCommandVehicleUnavailableError(RemoteCommandApplicationError):
    """Vehicle cannot currently accept a remote command."""

    def __init__(
        self,
        message: str = ("Vehicle is not ACTIVE and cannot accept remote commands."),
    ) -> None:
        super().__init__(
            code=ErrorCode.CONFLICT,
            message=message,
        )


class RemoteCommandIdempotencyConflictError(RemoteCommandApplicationError):
    """Idempotency key was reused for another request."""

    def __init__(
        self,
        message: str = ("Idempotency key was already used for a different remote-command request."),
    ) -> None:
        super().__init__(
            code=ErrorCode.CONFLICT,
            message=message,
        )
