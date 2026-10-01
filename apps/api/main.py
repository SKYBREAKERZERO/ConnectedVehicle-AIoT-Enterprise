from __future__ import annotations

from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="Connected Vehicle AIoT Enterprise",
        version="0.1.0",
        description="Enterprise Connected Vehicle, IoT and AIoT Platform",
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
