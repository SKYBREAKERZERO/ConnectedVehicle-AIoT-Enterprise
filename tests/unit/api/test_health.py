from fastapi.testclient import TestClient

from apps.api.main import app


def test_liveness_returns_ok() -> None:
    client = TestClient(app)

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
