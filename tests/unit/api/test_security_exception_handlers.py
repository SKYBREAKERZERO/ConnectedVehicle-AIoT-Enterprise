from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from enterprise_platform.errors.handlers import register_exception_handlers
from enterprise_platform.observability.middleware import (
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    http_observability_middleware,
)
from enterprise_platform.security.authorization import (
    AuthenticationRequiredError,
    AuthorizationDeniedError,
)
from enterprise_platform.security.permissions import Permission


def create_test_app() -> FastAPI:
    app = FastAPI()

    register_exception_handlers(app)
    app.middleware("http")(http_observability_middleware)

    @app.get("/authentication-required")
    async def authentication_required() -> None:
        raise AuthenticationRequiredError()

    @app.get("/authorization-denied")
    async def authorization_denied() -> None:
        raise AuthorizationDeniedError(Permission.OTA_MANAGE)

    return app


def test_authentication_required_returns_standard_401_contract() -> None:
    client = TestClient(create_test_app())

    response = client.get(
        "/authentication-required",
        headers={
            REQUEST_ID_HEADER: "request-auth-001",
            CORRELATION_ID_HEADER: "correlation-auth-001",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "error": {
            "code": "AUTHENTICATION_REQUIRED",
            "message": "Authentication is required.",
            "request_id": "request-auth-001",
            "correlation_id": "correlation-auth-001",
        }
    }

    assert response.headers[REQUEST_ID_HEADER] == "request-auth-001"
    assert response.headers[CORRELATION_ID_HEADER] == "correlation-auth-001"


def test_authorization_denied_returns_standard_403_contract() -> None:
    client = TestClient(create_test_app())

    response = client.get(
        "/authorization-denied",
        headers={
            REQUEST_ID_HEADER: "request-authz-001",
            CORRELATION_ID_HEADER: "correlation-authz-001",
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "error": {
            "code": "AUTHORIZATION_DENIED",
            "message": ("The caller is not authorized to perform this operation."),
            "request_id": "request-authz-001",
            "correlation_id": "correlation-authz-001",
        }
    }

    assert response.headers[REQUEST_ID_HEADER] == "request-authz-001"
    assert response.headers[CORRELATION_ID_HEADER] == "correlation-authz-001"


def test_authorization_response_does_not_expose_required_permission() -> None:
    client = TestClient(create_test_app())

    response = client.get("/authorization-denied")

    body = response.text

    assert response.status_code == 403
    assert Permission.OTA_MANAGE.value not in body
