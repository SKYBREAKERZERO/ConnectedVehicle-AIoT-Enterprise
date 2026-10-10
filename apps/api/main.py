from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from apps.api.routers.device_data import router as device_data_router
from apps.api.routers.remote_command import (
    router as remote_command_router,
)
from apps.api.service_auth import ServiceTokenMiddleware
from enterprise_platform.config.settings import get_settings
from enterprise_platform.database.credentials import load_runtime_database_settings
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
from enterprise_platform.security.oidc import OIDCMiddleware


def create_app() -> FastAPI:
    settings = get_settings()

    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(
        app: FastAPI,
    ) -> AsyncIterator[None]:
        engine = create_database_engine(
            await load_runtime_database_settings(settings, "application")
        )
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
        description=("Enterprise Connected Vehicle, IoT and AIoT Platform"),
        lifespan=lifespan,
    )

    app.add_middleware(ServiceTokenMiddleware, settings=settings)
    app.add_middleware(OIDCMiddleware, settings=settings)

    register_exception_handlers(app)

    app.middleware("http")(http_observability_middleware)

    configure_tracing(
        app,
        settings,
    )

    app.include_router(remote_command_router)
    app.include_router(device_data_router)

    @app.get(
        "/health/live",
        tags=["Health"],
        summary="Liveness probe",
    )
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", tags=["Health"], summary="Database readiness probe")
    async def readiness() -> dict[str, str]:
        try:
            async with asyncio.timeout(settings.database_health_timeout_seconds):
                async with app.state.database_engine.connect() as connection:
                    await connection.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        return {"status": "ready"}

    return app


app = create_app()
