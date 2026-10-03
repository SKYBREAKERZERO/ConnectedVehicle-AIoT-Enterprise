from __future__ import annotations

from enterprise_platform.errors.codes import ErrorCode


class ApplicationError(Exception):
    """Base class for errors that are safe to translate at application boundaries."""

    def __init__(
        self,
        *,
        code: ErrorCode,
        message: str,
    ) -> None:
        normalized_message = message.strip()

        if not normalized_message:
            raise ValueError("Application error message must not be empty.")

        self.code = code
        self.message = normalized_message

        super().__init__(normalized_message)


class InvalidRequestError(ApplicationError):
    def __init__(
        self,
        message: str = "The request is invalid.",
    ) -> None:
        super().__init__(
            code=ErrorCode.INVALID_REQUEST,
            message=message,
        )


class ResourceNotFoundError(ApplicationError):
    def __init__(
        self,
        message: str = "The requested resource was not found.",
    ) -> None:
        super().__init__(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message,
        )


class ConflictError(ApplicationError):
    def __init__(
        self,
        message: str = "The request conflicts with the current resource state.",
    ) -> None:
        super().__init__(
            code=ErrorCode.CONFLICT,
            message=message,
        )


class DependencyUnavailableError(ApplicationError):
    def __init__(
        self,
        message: str = "A required dependency is unavailable.",
    ) -> None:
        super().__init__(
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message=message,
        )


class DependencyTimeoutError(ApplicationError):
    def __init__(
        self,
        message: str = "A required dependency timed out.",
    ) -> None:
        super().__init__(
            code=ErrorCode.DEPENDENCY_TIMEOUT,
            message=message,
        )
