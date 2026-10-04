from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
)

from apps.api.main import create_app


def test_api_lifespan_initializes_database_runtime() -> None:
    app = create_app()

    with TestClient(app) as client:
        response = client.get("/health/live")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

        assert isinstance(
            app.state.database_engine,
            AsyncEngine,
        )

        assert isinstance(
            app.state.session_factory,
            async_sessionmaker,
        )
