from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.api.main import create_app
from connected_vehicle.ota.contracts import CancelJob, FirmwareRegistration, JobRequest
from connected_vehicle.ota.service import operation_key
from enterprise_platform.errors.base import InvalidRequestError


def firmware() -> dict[str, object]:
    return dict(
        ecu_type="body",
        hardware_version="hw-1",
        version="2.0.0",
        artifact_bucket="local-firmware",
        artifact_key="body/v2.bin",
        artifact_version="version-1",
        sha256="a" * 64,
        size_bytes=1024,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": "forged"},
        {"sha256": "bad"},
        {"sha256": "A" * 64},
        {"size_bytes": 0},
        {"size_bytes": True},
        {"size_bytes": 4294967297},
        {"artifact_version": "null"},
        {"artifact_version": " "},
        {"artifact_key": "bad\nkey"},
        {"hardware_version": "../hw"},
    ],
)
def test_firmware_contract_rejects_untrusted_metadata(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FirmwareRegistration.model_validate(firmware() | change)


def test_jobs_cannot_accept_caller_status_or_tenant() -> None:
    with pytest.raises(ValidationError):
        JobRequest.model_validate({"release_id": "a" * 36, "status": "succeeded"})
    with pytest.raises(ValidationError):
        CancelJob(reason=" ")
    with pytest.raises(InvalidRequestError):
        operation_key(" ")


def test_ota_openapi_defines_explicit_permissions_and_durable_intent() -> None:
    schema = create_app().openapi()
    routes = schema["paths"]
    assert "202" in routes["/vehicles/{vehicle_id}/ecus/{ecu_id}/ota-jobs"]["post"]["responses"]
    assert routes["/ota/jobs/{job_id}/cancel"]["post"]["operationId"] == "cancelOTAJob"
    assert schema["components"]["schemas"]["JobView"]["properties"]["status"]["enum"] == [
        "pending_verification",
        "cancelled",
    ]
    # Unauthenticated requests must fail before a missing DB dependency can be used.
    response = TestClient(create_app(), raise_server_exceptions=False).get("/ota/firmware-releases")
    assert response.status_code == 401
