from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.engine import (
    create_database_engine,
)
from enterprise_platform.database.session import (
    create_session_factory,
)
from enterprise_platform.errors import register_exception_handlers
from enterprise_platform.observability.logging import configure_logging
from enterprise_platform.observability.middleware import (
    http_observability_middleware,
)
from enterprise_platform.observability.tracing import configure_tracing


def create_app() -> FastAPI:
    settings = get_settings()

    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(
        app: FastAPI,
    ) -> AsyncIterator[None]:
        engine = create_database_engine(settings)
        session_factory = create_session_factory(engine)

        app.state.database_engine = engine
        app.state.session_factory = session_factory

        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(
        title="Connected Vehicle AIoT Enterprise",
        version="0.1.0",
        description="Enterprise Connected Vehicle, IoT and AIoT Platform",
        lifespan=lifespan,
    )

    register_exception_handlers(app)

    app.middleware("http")(http_observability_middleware)

    configure_tracing(
        app,
        settings,
    )

    @app.get(
        "/health/live",
        tags=["Health"],
        summary="Liveness probe",
    )
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
