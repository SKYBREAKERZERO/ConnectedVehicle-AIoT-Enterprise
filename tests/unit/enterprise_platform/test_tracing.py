from __future__ import annotations

from fastapi import FastAPI
from opentelemetry.sdk.trace import TracerProvider

from enterprise_platform.config.settings import Settings
from enterprise_platform.observability.tracing import (
    configure_tracing,
    get_current_trace_id,
)


def test_get_current_trace_id_is_none_without_active_span() -> None:
    assert get_current_trace_id() is None


def test_get_current_trace_id_returns_valid_hex_trace_id() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer(__name__)

    with tracer.start_as_current_span("test-span"):
        trace_id = get_current_trace_id()

        assert trace_id is not None
        assert len(trace_id) == 32

        int(trace_id, 16)

    provider.shutdown()


def test_configure_tracing_does_nothing_when_disabled() -> None:
    app = FastAPI()

    settings = Settings(
        _env_file=None,
        tracing_enabled=False,
    )

    assert configure_tracing(app, settings) is False


def test_configure_tracing_is_idempotent_for_same_app() -> None:
    app = FastAPI()

    settings = Settings(
        _env_file=None,
        tracing_enabled=True,
    )

    assert configure_tracing(app, settings) is True
    assert configure_tracing(app, settings) is False
