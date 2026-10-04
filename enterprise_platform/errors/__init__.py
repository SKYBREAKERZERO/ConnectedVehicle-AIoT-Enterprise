from __future__ import annotations

from typing import TYPE_CHECKING

from enterprise_platform.errors.base import (
    ApplicationError,
    ConflictError,
    DependencyTimeoutError,
    DependencyUnavailableError,
    InvalidRequestError,
    ResourceNotFoundError,
)
from enterprise_platform.errors.codes import ErrorCode

__all__ = [
    "ApplicationError",
    "ConflictError",
    "DependencyTimeoutError",
    "DependencyUnavailableError",
    "ErrorCode",
    "InvalidRequestError",
    "ResourceNotFoundError",
    "register_exception_handlers",
]


if TYPE_CHECKING:
    from fastapi import FastAPI


def register_exception_handlers(
    app: FastAPI,
) -> None:
    from enterprise_platform.errors.handlers import (
        register_exception_handlers as _register_exception_handlers,
    )

    _register_exception_handlers(app)
