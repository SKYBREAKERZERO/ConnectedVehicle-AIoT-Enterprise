from __future__ import annotations

from enterprise_platform.observability.context import (
    bind_observability_context,
    get_observability_context,
)


def test_observability_context_is_empty_by_default() -> None:
    context = get_observability_context()

    assert context.request_id is None
    assert context.correlation_id is None
    assert context.trace_id is None


def test_observability_context_is_bound_inside_scope() -> None:
    with bind_observability_context(
        request_id="request-123",
        correlation_id="correlation-456",
        trace_id="trace-789",
    ):
        context = get_observability_context()

        assert context.request_id == "request-123"
        assert context.correlation_id == "correlation-456"
        assert context.trace_id == "trace-789"


def test_observability_context_is_reset_after_scope() -> None:
    with bind_observability_context(
        request_id="request-123",
        correlation_id="correlation-456",
    ):
        assert get_observability_context().request_id == "request-123"

    context = get_observability_context()

    assert context.request_id is None
    assert context.correlation_id is None
    assert context.trace_id is None


def test_nested_observability_context_restores_parent() -> None:
    with bind_observability_context(
        request_id="parent-request",
        correlation_id="parent-correlation",
    ):
        with bind_observability_context(
            request_id="child-request",
            correlation_id="child-correlation",
        ):
            assert get_observability_context().request_id == "child-request"

        context = get_observability_context()

        assert context.request_id == "parent-request"
        assert context.correlation_id == "parent-correlation"
