from __future__ import annotations

from threading import Lock

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider

from enterprise_platform.config.settings import Settings

_provider_lock = Lock()
_provider_configured = False

_TRACING_INSTRUMENTED_STATE_KEY = "_connected_vehicle_tracing_instrumented"


def get_current_trace_id() -> str | None:
    """Return the active OpenTelemetry trace ID as a 32-character hex string."""

    span_context = trace.get_current_span().get_span_context()

    if not span_context.is_valid:
        return None

    return f"{span_context.trace_id:032x}"


def _configure_tracer_provider(settings: Settings) -> None:
    global _provider_configured

    with _provider_lock:
        if _provider_configured:
            return

        current_provider = trace.get_tracer_provider()

        if not isinstance(current_provider, TracerProvider):
            provider = TracerProvider(
                resource=Resource.create(
                    {
                        "service.name": settings.app_name,
                        "deployment.environment.name": settings.app_env.value,
                    }
                )
            )
            trace.set_tracer_provider(provider)

        _provider_configured = True


def configure_tracing(
    app: FastAPI,
    settings: Settings,
) -> bool:
    """Configure OpenTelemetry tracing for one FastAPI application.

    Returns True when instrumentation was installed by this call.
    Returns False when tracing is disabled or the application was already
    instrumented.
    """

    if not settings.tracing_enabled:
        return False

    if getattr(
        app.state,
        _TRACING_INSTRUMENTED_STATE_KEY,
        False,
    ):
        return False

    _configure_tracer_provider(settings)

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=trace.get_tracer_provider(),
    )

    setattr(
        app.state,
        _TRACING_INSTRUMENTED_STATE_KEY,
        True,
    )

    return True
