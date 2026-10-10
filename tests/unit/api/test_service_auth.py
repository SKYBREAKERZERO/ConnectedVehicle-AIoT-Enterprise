from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from apps.api.security import get_remote_command_security_context
from apps.api.service_auth import ServiceTokenMiddleware
from enterprise_platform.config.settings import Settings
from enterprise_platform.errors import register_exception_handlers
from enterprise_platform.security.context import SecurityContext, get_security_context

TOKEN = "service-credential-" + "a" * 40


def client() -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)
    app.add_middleware(
        ServiceTokenMiddleware,
        settings=Settings.model_construct(
            api_service_token=SecretStr(TOKEN),
            api_service_tenant_id="fixed-tenant",
        ),
    )

    @app.get("/identity")
    def identity(
        context: Annotated[SecurityContext, Depends(get_remote_command_security_context)],
    ) -> dict[str, str]:
        return {"tenant": context.principal.tenant_id or "", "id": context.principal.principal_id}

    return TestClient(app)


@pytest.mark.parametrize("authorization", ["", "Bearer wrong", "Basic " + TOKEN])
def test_untrusted_token_does_not_authenticate(authorization: str) -> None:
    response = client().get("/identity", headers={"Authorization": authorization})
    assert response.status_code == 401


def test_trusted_service_token_uses_configured_tenant_and_context_does_not_leak() -> None:
    http = client()
    response = http.get(
        "/identity", headers={"Authorization": "Bearer " + TOKEN, "X-Tenant-ID": "attacker-tenant"}
    )
    assert response.status_code == 200 and response.json()["tenant"] == "fixed-tenant"
    assert get_security_context() is None
    assert http.get("/identity").status_code == 401


@pytest.mark.parametrize(
    "updates",
    [
        {"api_service_token": SecretStr("short"), "api_service_tenant_id": "tenant"},
        {"api_service_token": SecretStr(TOKEN)},
        {"api_service_tenant_id": "tenant"},
        {"api_service_token": SecretStr(TOKEN), "api_service_tenant_id": " "},
        {"outbox_lease_seconds": 5},
        {"worker_operation_timeout_seconds": 60, "outbox_lease_seconds": 100},
    ],
)
def test_invalid_runtime_contract_is_rejected(updates: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Settings.model_validate(updates)
