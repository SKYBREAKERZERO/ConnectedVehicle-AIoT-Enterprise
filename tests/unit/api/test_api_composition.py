from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
)

from apps.api.main import create_app
from enterprise_platform.config.settings import Settings


def test_api_lifespan_initializes_database_runtime() -> None:
    app = create_app()

    with (
        patch(
            "apps.api.main.load_runtime_database_settings",
            new=AsyncMock(return_value=Settings.model_construct(database_username="app_user")),
        ),
        TestClient(app) as client,
    ):
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
