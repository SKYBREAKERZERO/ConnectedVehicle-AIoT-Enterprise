from __future__ import annotations

import re
from time import perf_counter
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import RequestResponseEndpoint

from enterprise_platform.observability.context import (
    bind_observability_context,
)
from enterprise_platform.observability.logging import get_logger
from enterprise_platform.observability.tracing import get_current_trace_id

REQUEST_ID_HEADER = "X-Request-ID"
CORRELATION_ID_HEADER = "X-Correlation-ID"

_OBSERVABILITY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

logger = get_logger("http")


def normalize_observability_id(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip()

    if not _OBSERVABILITY_ID_PATTERN.fullmatch(normalized):
        return None

    return normalized


def create_request_id() -> str:
    return str(uuid4())


async def http_observability_middleware(
    request: Request,
    call_next: RequestResponseEndpoint,
) -> Response:
    request_id = (
        normalize_observability_id(request.headers.get(REQUEST_ID_HEADER)) or create_request_id()
    )

    correlation_id = (
        normalize_observability_id(request.headers.get(CORRELATION_ID_HEADER)) or request_id
    )

    trace_id = get_current_trace_id()

    request.state.request_id = request_id
    request.state.correlation_id = correlation_id
    request.state.trace_id = trace_id

    started_at = perf_counter()

    with bind_observability_context(
        request_id=request_id,
        correlation_id=correlation_id,
        trace_id=trace_id,
    ):
        logger.info(
            "http_request_started",
            method=request.method,
            path=request.url.path,
        )

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round(
                (perf_counter() - started_at) * 1000,
                3,
            )

            logger.exception(
                "http_request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
            )

            raise

        duration_ms = round(
            (perf_counter() - started_at) * 1000,
            3,
        )

        response.headers[REQUEST_ID_HEADER] = request_id
        response.headers[CORRELATION_ID_HEADER] = correlation_id

        logger.info(
            "http_request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        return response
