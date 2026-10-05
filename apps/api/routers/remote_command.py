from __future__ import annotations

from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, status

from apps.api.contracts import (
    ErrorResponseContract,
    IssueRemoteCommandRequest,
    IssueRemoteCommandResponse,
    RemoteCommandStatusContract,
    RemoteCommandTypeContract,
)
from apps.api.dependencies import (
    get_issue_remote_command_service,
)
from apps.api.security import (
    get_remote_command_security_context,
)
from connected_vehicle.remote_command import RemoteCommandType
from connected_vehicle.remote_command.service import (
    IssueRemoteCommandService,
)
from connected_vehicle.vehicle import VehicleId
from enterprise_platform.errors import InvalidRequestError
from enterprise_platform.security.context import SecurityContext

router = APIRouter(
    tags=["Remote Commands"],
)


@router.post(
    "/vehicles/{vehicle_id}/commands",
    operation_id="issueRemoteCommand",
    summary="Issue a remote vehicle command",
    description=(
        "Accept a remote command for asynchronous execution. "
        "HTTP 202 confirms durable cloud acceptance, not "
        "successful vehicle execution."
    ),
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IssueRemoteCommandResponse,
    responses={
        202: {
            "description": ("Remote command accepted for asynchronous execution."),
        },
        400: {
            "model": ErrorResponseContract,
            "description": "Invalid request.",
        },
        401: {
            "model": ErrorResponseContract,
            "description": "Authentication required.",
        },
        403: {
            "model": ErrorResponseContract,
            "description": "Authorization denied.",
        },
        404: {
            "model": ErrorResponseContract,
            "description": ("Vehicle not found in the tenant scope."),
        },
        409: {
            "model": ErrorResponseContract,
            "description": ("Vehicle state or idempotency conflict."),
        },
        422: {
            "model": ErrorResponseContract,
            "description": "Request contract validation failed.",
        },
        500: {
            "model": ErrorResponseContract,
            "description": "Unexpected internal error.",
        },
    },
)
async def issue_remote_command(
    vehicle_id: UUID,
    payload: IssueRemoteCommandRequest,
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=255,
        ),
    ],
    security_context: Annotated[
        SecurityContext,
        Depends(get_remote_command_security_context),
    ],
    service: Annotated[
        IssueRemoteCommandService,
        Depends(get_issue_remote_command_service),
    ],
) -> IssueRemoteCommandResponse:
    normalized_idempotency_key = idempotency_key.strip()

    if not normalized_idempotency_key:
        raise InvalidRequestError("Idempotency-Key must not be empty.")

    tenant_id = cast(
        str,
        security_context.principal.tenant_id,
    )

    result = await service.issue(
        vehicle_id=VehicleId(str(vehicle_id)),
        tenant_id=tenant_id,
        command_type=RemoteCommandType(payload.command_type.value),
        idempotency_key=normalized_idempotency_key,
    )

    command = result.command

    return IssueRemoteCommandResponse(
        command_id=UUID(command.id.value),
        vehicle_id=UUID(command.vehicle_id.value),
        command_type=RemoteCommandTypeContract(command.command_type.value),
        status=RemoteCommandStatusContract(command.status.value),
        created=result.created,
        created_at=command.created_at,
        expires_at=command.expires_at,
    )
