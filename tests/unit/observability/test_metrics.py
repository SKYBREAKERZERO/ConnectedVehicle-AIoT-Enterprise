from fastapi import FastAPI
from fastapi.testclient import TestClient

from enterprise_platform.observability.metrics import configure_metrics
from tests.settings_helpers import isolated_settings


def test_scrape_is_protected_and_labels_are_bounded() -> None:
    app = FastAPI()
    configure_metrics(app, isolated_settings(_env_file=None, metrics_token="a" * 64))

    @app.get("/vehicles/{vehicle_id}")
    def vehicle(vehicle_id: str) -> dict[str, str]:
        return {"id": vehicle_id}

    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 403
        assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 403
        for identifier in ("secret-vehicle-1", "secret-vehicle-2"):
            assert client.get("/vehicles/" + identifier).status_code == 200
        assert client.get("/not-found-private-path").status_code == 404
        response = client.get("/metrics", headers={"Authorization": "Bearer " + "a" * 64})
        assert response.status_code == 200
        assert "secret-vehicle" not in response.text and "private-path" not in response.text
        assert 'route="/vehicles/{vehicle_id}"' in response.text
        assert 'route="unmatched"' in response.text
        assert "vehicle_http_duration_seconds" in response.text


def test_metrics_disabled_without_explicit_scrape_credential() -> None:
    app = FastAPI()
    configure_metrics(app, isolated_settings(_env_file=None))
    assert TestClient(app).get("/metrics").status_code == 403
