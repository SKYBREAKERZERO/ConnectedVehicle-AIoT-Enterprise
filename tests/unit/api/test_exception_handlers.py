from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from enterprise_platform.errors import (
    ConflictError,
    DependencyTimeoutError,
    DependencyUnavailableError,
    InvalidRequestError,
    ResourceNotFoundError,
    register_exception_handlers,
)
from enterprise_platform.observability.middleware import (
    http_observability_middleware,
)


def create_test_app() -> FastAPI:
    app = FastAPI()

    register_exception_handlers(app)
    app.middleware("http")(http_observability_middleware)

    @app.get("/invalid")
    async def invalid() -> None:
        raise InvalidRequestError()

    @app.get("/missing")
    async def missing() -> None:
        raise ResourceNotFoundError()

    @app.get("/conflict")
    async def conflict() -> None:
        raise ConflictError()

    @app.get("/dependency-unavailable")
    async def dependency_unavailable() -> None:
        raise DependencyUnavailableError()

    @app.get("/dependency-timeout")
    async def dependency_timeout() -> None:
        raise DependencyTimeoutError()

    @app.get("/unexpected")
    async def unexpected() -> None:
        raise RuntimeError("database-password-must-never-leak")

    class RequestBody(BaseModel):
        vehicle_id: int

    @app.post("/validation")
    async def validation(payload: RequestBody) -> dict[str, int]:
        return {"vehicle_id": payload.vehicle_id}

    return app


def test_application_errors_are_mapped_to_http_status_codes() -> None:
    client = TestClient(create_test_app())

    cases = [
        ("/invalid", 400, "INVALID_REQUEST"),
        ("/missing", 404, "RESOURCE_NOT_FOUND"),
        ("/conflict", 409, "CONFLICT"),
        (
            "/dependency-unavailable",
            503,
            "DEPENDENCY_UNAVAILABLE",
        ),
        (
            "/dependency-timeout",
            504,
            "DEPENDENCY_TIMEOUT",
        ),
    ]

    for path, expected_status, expected_code in cases:
        response = client.get(
            path,
            headers={
                "X-Request-ID": "req-test",
                "X-Correlation-ID": "corr-test",
            },
        )

        assert response.status_code == expected_status

        payload = response.json()["error"]

        assert payload["code"] == expected_code
        assert payload["request_id"] == "req-test"
        assert payload["correlation_id"] == "corr-test"

        assert response.headers["X-Request-ID"] == "req-test"
        assert response.headers["X-Correlation-ID"] == "corr-test"


def test_validation_error_uses_standard_error_contract() -> None:
    client = TestClient(create_test_app())

    response = client.post(
        "/validation",
        json={"vehicle_id": "not-an-integer"},
        headers={
            "X-Request-ID": "req-validation",
            "X-Correlation-ID": "corr-validation",
        },
    )

    assert response.status_code == 422

    payload = response.json()["error"]

    assert payload == {
        "code": "INVALID_REQUEST",
        "message": "Request validation failed.",
        "request_id": "req-validation",
        "correlation_id": "corr-validation",
    }


def test_unexpected_error_is_safe_and_preserves_request_context() -> None:
    client = TestClient(
        create_test_app(),
        raise_server_exceptions=False,
    )

    response = client.get(
        "/unexpected",
        headers={
            "X-Request-ID": "req-unexpected",
            "X-Correlation-ID": "corr-unexpected",
        },
    )

    assert response.status_code == 500

    payload = response.json()["error"]

    assert payload == {
        "code": "INTERNAL_ERROR",
        "message": "An unexpected error occurred.",
        "request_id": "req-unexpected",
        "correlation_id": "corr-unexpected",
    }

    response_text = response.text

    assert "database-password-must-never-leak" not in response_text

    assert response.headers["X-Request-ID"] == "req-unexpected"
    assert response.headers["X-Correlation-ID"] == "corr-unexpected"
