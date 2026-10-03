from __future__ import annotations

from typing import Final, TypedDict, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from enterprise_platform.errors.base import ApplicationError
from enterprise_platform.errors.codes import ErrorCode
from enterprise_platform.observability.context import get_observability_context
from enterprise_platform.observability.logging import get_logger
from enterprise_platform.observability.middleware import (
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
)
from enterprise_platform.security.authorization import (
    AuthenticationRequiredError,
    AuthorizationDeniedError,
)

logger = get_logger("errors")


_ERROR_STATUS_CODES: Final[dict[ErrorCode, int]] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.AUTHENTICATION_REQUIRED: 401,
    ErrorCode.AUTHORIZATION_DENIED: 403,
    ErrorCode.RESOURCE_NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.DEPENDENCY_UNAVAILABLE: 503,
    ErrorCode.DEPENDENCY_TIMEOUT: 504,
    ErrorCode.INTERNAL_ERROR: 500,
}


class ErrorBody(TypedDict):
    code: str
    message: str
    request_id: str | None
    correlation_id: str | None


class ErrorResponsePayload(TypedDict):
    error: ErrorBody


def _resolve_request_identifiers(
    request: Request,
) -> tuple[str | None, str | None]:
    context = get_observability_context()

    state_request_id = getattr(
        request.state,
        "request_id",
        None,
    )
    state_correlation_id = getattr(
        request.state,
        "correlation_id",
        None,
    )

    request_id = (
        state_request_id
        if isinstance(state_request_id, str) and state_request_id
        else context.request_id
    )

    correlation_id = (
        state_correlation_id
        if isinstance(state_correlation_id, str) and state_correlation_id
        else context.correlation_id
    )

    return request_id, correlation_id


def _build_error_response(
    request: Request,
    *,
    status_code: int,
    code: ErrorCode,
    message: str,
) -> JSONResponse:
    request_id, correlation_id = _resolve_request_identifiers(request)

    payload: ErrorResponsePayload = {
        "error": {
            "code": code.value,
            "message": message,
            "request_id": request_id,
            "correlation_id": correlation_id,
        }
    }

    headers: dict[str, str] = {}

    if request_id is not None:
        headers[REQUEST_ID_HEADER] = request_id

    if correlation_id is not None:
        headers[CORRELATION_ID_HEADER] = correlation_id

    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers=headers,
    )


async def application_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    error = cast(ApplicationError, exc)

    status_code = _ERROR_STATUS_CODES.get(
        error.code,
        500,
    )

    logger.warning(
        "application_error_handled",
        error_code=error.code.value,
        status_code=status_code,
    )

    return _build_error_response(
        request,
        status_code=status_code,
        code=error.code,
        message=error.message,
    )


async def authentication_required_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    del exc

    logger.warning(
        "authentication_required",
        status_code=401,
    )

    return _build_error_response(
        request,
        status_code=401,
        code=ErrorCode.AUTHENTICATION_REQUIRED,
        message="Authentication is required.",
    )


async def authorization_denied_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    error = cast(AuthorizationDeniedError, exc)

    logger.warning(
        "authorization_denied",
        permission=error.permission.value,
        status_code=403,
    )

    return _build_error_response(
        request,
        status_code=403,
        code=ErrorCode.AUTHORIZATION_DENIED,
        message="The caller is not authorized to perform this operation.",
    )


async def validation_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    error = cast(RequestValidationError, exc)

    logger.warning(
        "request_validation_failed",
        error_count=len(error.errors()),
        status_code=422,
    )

    return _build_error_response(
        request,
        status_code=422,
        code=ErrorCode.INVALID_REQUEST,
        message="Request validation failed.",
    )


async def unexpected_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    del exc

    return _build_error_response(
        request,
        status_code=500,
        code=ErrorCode.INTERNAL_ERROR,
        message="An unexpected error occurred.",
    )


def register_exception_handlers(
    app: FastAPI,
) -> None:
    app.add_exception_handler(
        ApplicationError,
        application_error_handler,
    )

    app.add_exception_handler(
        AuthenticationRequiredError,
        authentication_required_handler,
    )

    app.add_exception_handler(
        AuthorizationDeniedError,
        authorization_denied_handler,
    )

    app.add_exception_handler(
        RequestValidationError,
        validation_error_handler,
    )

    app.add_exception_handler(
        Exception,
        unexpected_error_handler,
    )
