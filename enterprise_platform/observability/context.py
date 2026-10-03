from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from structlog.typing import EventDict, WrappedLogger

_request_id: ContextVar[str | None] = ContextVar(
    "observability_request_id",
    default=None,
)
_correlation_id: ContextVar[str | None] = ContextVar(
    "observability_correlation_id",
    default=None,
)
_trace_id: ContextVar[str | None] = ContextVar(
    "observability_trace_id",
    default=None,
)


@dataclass(frozen=True, slots=True)
class ObservabilityContext:
    request_id: str | None
    correlation_id: str | None
    trace_id: str | None


def get_observability_context() -> ObservabilityContext:
    return ObservabilityContext(
        request_id=_request_id.get(),
        correlation_id=_correlation_id.get(),
        trace_id=_trace_id.get(),
    )


@contextmanager
def bind_observability_context(
    *,
    request_id: str,
    correlation_id: str,
    trace_id: str | None = None,
) -> Iterator[None]:
    request_token = _request_id.set(request_id)
    correlation_token = _correlation_id.set(correlation_id)
    trace_token = _trace_id.set(trace_id)

    try:
        yield
    finally:
        _trace_id.reset(trace_token)
        _correlation_id.reset(correlation_token)
        _request_id.reset(request_token)


def merge_observability_context(
    logger: WrappedLogger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    del logger, method_name

    context = get_observability_context()

    if context.request_id is not None:
        event_dict["request_id"] = context.request_id

    if context.correlation_id is not None:
        event_dict["correlation_id"] = context.correlation_id

    if context.trace_id is not None:
        event_dict["trace_id"] = context.trace_id

    return event_dict
