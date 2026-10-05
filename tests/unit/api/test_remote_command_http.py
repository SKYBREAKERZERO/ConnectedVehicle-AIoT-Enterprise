from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from apps.api.dependencies import (
    get_issue_remote_command_service,
)
from apps.api.main import create_app
from apps.api.security import (
    get_remote_command_security_context,
)
from connected_vehicle.remote_command import (
    RemoteCommand,
    RemoteCommandId,
    RemoteCommandType,
)
from connected_vehicle.remote_command.application_errors import (
    RemoteCommandIdempotencyConflictError,
    RemoteCommandVehicleNotFoundError,
    RemoteCommandVehicleUnavailableError,
)
from connected_vehicle.remote_command.service import (
    IssueRemoteCommandResult,
)
from connected_vehicle.vehicle import VehicleId
from enterprise_platform.security.context import SecurityContext
from enterprise_platform.security.exceptions import (
    AuthorizationDeniedError,
)
from enterprise_platform.security.identity import (
    Principal,
    PrincipalType,
    Role,
)
from enterprise_platform.security.permissions import Permission

VEHICLE_ID = "22222222-2222-4222-8222-222222222222"
COMMAND_ID = "11111111-1111-4111-8111-111111111111"

FIXED_NOW = datetime(
    2026,
    10,
    4,
    12,
    0,
    tzinfo=UTC,
)


class StubIssueRemoteCommandService:
    def __init__(
        self,
        *,
        result: IssueRemoteCommandResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[
            tuple[
                str,
                str,
                RemoteCommandType,
                str,
            ]
        ] = []

    async def issue(
        self,
        *,
        vehicle_id: VehicleId,
        tenant_id: str,
        command_type: RemoteCommandType,
        idempotency_key: str,
    ) -> IssueRemoteCommandResult:
        self.calls.append(
            (
                vehicle_id.value,
                tenant_id,
                command_type,
                idempotency_key,
            )
        )

        if self.error is not None:
            raise self.error

        if self.result is None:
            raise RuntimeError("Stub result was not configured.")

        return self.result


def create_result(
    *,
    created: bool,
) -> IssueRemoteCommandResult:
    command = RemoteCommand.request(
        vehicle_id=VehicleId(VEHICLE_ID),
        tenant_id="tenant-001",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="idem-001",
        command_id=RemoteCommandId(COMMAND_ID),
        now=FIXED_NOW,
    )

    return IssueRemoteCommandResult(
        command=command,
        created=created,
    )


def authorized_security_context() -> SecurityContext:
    return SecurityContext(
        principal=Principal(
            principal_id="user-001",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-001",
            roles=frozenset(
                {
                    Role.VEHICLE_OWNER,
                }
            ),
        )
    )


def denied_security_context() -> SecurityContext:
    raise AuthorizationDeniedError(Permission.VEHICLE_COMMAND)


SecurityDependency = Callable[
    [],
    SecurityContext,
]


def create_test_client(
    service: StubIssueRemoteCommandService,
    *,
    security_dependency: SecurityDependency | None = (authorized_security_context),
) -> TestClient:
    app = create_app()

    app.dependency_overrides[get_issue_remote_command_service] = lambda: service

    if security_dependency is not None:
        app.dependency_overrides[get_remote_command_security_context] = security_dependency

    return TestClient(
        app,
        raise_server_exceptions=False,
    )


@pytest.mark.parametrize(
    "created",
    [
        True,
        False,
    ],
)
def test_post_remote_command_returns_202_accepted(
    created: bool,
) -> None:
    service = StubIssueRemoteCommandService(result=create_result(created=created))

    client = create_test_client(service)

    response = client.post(
        f"/vehicles/{VEHICLE_ID}/commands",
        headers={
            "Idempotency-Key": " idem-001 ",
        },
        json={
            "command_type": "lock",
        },
    )

    assert response.status_code == 202

    body = response.json()

    assert body["command_id"] == COMMAND_ID
    assert body["vehicle_id"] == VEHICLE_ID
    assert body["command_type"] == "lock"
    assert body["status"] == "requested"
    assert body["created"] is created

    assert service.calls == [
        (
            VEHICLE_ID,
            "tenant-001",
            RemoteCommandType.LOCK,
            "idem-001",
        )
    ]


def test_post_remote_command_requires_authentication() -> None:
    service = StubIssueRemoteCommandService(result=create_result(created=True))

    client = create_test_client(
        service,
        security_dependency=None,
    )

    response = client.post(
        f"/vehicles/{VEHICLE_ID}/commands",
        headers={
            "Idempotency-Key": "idem-001",
        },
        json={
            "command_type": "lock",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_post_remote_command_requires_permission() -> None:
    service = StubIssueRemoteCommandService(result=create_result(created=True))

    client = create_test_client(
        service,
        security_dependency=denied_security_context,
    )

    response = client.post(
        f"/vehicles/{VEHICLE_ID}/commands",
        headers={
            "Idempotency-Key": "idem-001",
        },
        json={
            "command_type": "lock",
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTHORIZATION_DENIED"


@pytest.mark.parametrize(
    (
        "error",
        "expected_status",
        "expected_code",
    ),
    [
        (
            RemoteCommandVehicleNotFoundError(),
            404,
            "RESOURCE_NOT_FOUND",
        ),
        (
            RemoteCommandVehicleUnavailableError(),
            409,
            "CONFLICT",
        ),
        (
            RemoteCommandIdempotencyConflictError(),
            409,
            "CONFLICT",
        ),
    ],
)
def test_post_remote_command_maps_application_errors(
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    service = StubIssueRemoteCommandService(error=error)

    client = create_test_client(service)

    response = client.post(
        f"/vehicles/{VEHICLE_ID}/commands",
        headers={
            "Idempotency-Key": "idem-001",
        },
        json={
            "command_type": "lock",
        },
    )

    assert response.status_code == expected_status

    assert response.json()["error"]["code"] == expected_code


def test_post_remote_command_rejects_blank_idempotency_key() -> None:
    service = StubIssueRemoteCommandService(result=create_result(created=True))

    client = create_test_client(service)

    response = client.post(
        f"/vehicles/{VEHICLE_ID}/commands",
        headers={
            "Idempotency-Key": "   ",
        },
        json={
            "command_type": "lock",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert service.calls == []


@pytest.mark.parametrize(
    (
        "path",
        "headers",
        "payload",
    ),
    [
        (
            f"/vehicles/{VEHICLE_ID}/commands",
            {},
            {
                "command_type": "lock",
            },
        ),
        (
            f"/vehicles/{VEHICLE_ID}/commands",
            {
                "Idempotency-Key": "idem-001",
            },
            {
                "command_type": "warp",
            },
        ),
        (
            f"/vehicles/{VEHICLE_ID}/commands",
            {
                "Idempotency-Key": "idem-001",
            },
            {
                "command_type": "lock",
                "unexpected": True,
            },
        ),
        (
            "/vehicles/not-a-uuid/commands",
            {
                "Idempotency-Key": "idem-001",
            },
            {
                "command_type": "lock",
            },
        ),
    ],
)
def test_post_remote_command_validation_uses_standard_422_contract(
    path: str,
    headers: dict[str, str],
    payload: dict[str, object],
) -> None:
    service = StubIssueRemoteCommandService(result=create_result(created=True))

    client = create_test_client(service)

    response = client.post(
        path,
        headers=headers,
        json=payload,
    )

    assert response.status_code == 422

    assert response.json()["error"]["code"] == "INVALID_REQUEST"
