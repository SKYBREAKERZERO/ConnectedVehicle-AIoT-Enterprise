from __future__ import annotations

from uuid import UUID

from fastapi import FastAPI
from fastapi.testclient import TestClient

from enterprise_platform.observability.context import (
    get_observability_context,
)
from enterprise_platform.observability.middleware import (
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    http_observability_middleware,
)


def create_test_app() -> FastAPI:
    app = FastAPI()
    app.middleware("http")(http_observability_middleware)

    @app.get("/context")
    async def context() -> dict[str, str | None]:
        observability_context = get_observability_context()

        return {
            "request_id": observability_context.request_id,
            "correlation_id": observability_context.correlation_id,
        }

    return app


def test_middleware_generates_request_and_correlation_ids() -> None:
    client = TestClient(create_test_app())

    response = client.get("/context")

    assert response.status_code == 200

    request_id = response.headers[REQUEST_ID_HEADER]
    correlation_id = response.headers[CORRELATION_ID_HEADER]

    UUID(request_id)

    assert correlation_id == request_id

    assert response.json() == {
        "request_id": request_id,
        "correlation_id": correlation_id,
    }


def test_middleware_preserves_valid_incoming_ids() -> None:
    client = TestClient(create_test_app())

    response = client.get(
        "/context",
        headers={
            REQUEST_ID_HEADER: "request-123",
            CORRELATION_ID_HEADER: "correlation-456",
        },
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER] == "request-123"
    assert response.headers[CORRELATION_ID_HEADER] == "correlation-456"

    assert response.json() == {
        "request_id": "request-123",
        "correlation_id": "correlation-456",
    }


def test_middleware_replaces_invalid_request_id() -> None:
    client = TestClient(create_test_app())

    response = client.get(
        "/context",
        headers={
            REQUEST_ID_HEADER: "invalid request id",
        },
    )

    assert response.status_code == 200

    request_id = response.headers[REQUEST_ID_HEADER]

    assert request_id != "invalid request id"
    UUID(request_id)

    assert response.headers[CORRELATION_ID_HEADER] == request_id


def test_middleware_keeps_correlation_id_when_request_id_is_generated() -> None:
    client = TestClient(create_test_app())

    response = client.get(
        "/context",
        headers={
            REQUEST_ID_HEADER: "invalid request id",
            CORRELATION_ID_HEADER: "upstream-correlation-123",
        },
    )

    request_id = response.headers[REQUEST_ID_HEADER]

    UUID(request_id)

    assert response.headers[CORRELATION_ID_HEADER] == "upstream-correlation-123"
