from __future__ import annotations

import pytest

from connected_vehicle.remote_command.application_errors import (
    RemoteCommandIdempotencyConflictError,
    RemoteCommandVehicleNotFoundError,
    RemoteCommandVehicleUnavailableError,
)
from enterprise_platform.errors.base import ApplicationError
from enterprise_platform.errors.codes import ErrorCode


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (
            RemoteCommandVehicleNotFoundError(),
            ErrorCode.RESOURCE_NOT_FOUND,
        ),
        (
            RemoteCommandVehicleUnavailableError(),
            ErrorCode.CONFLICT,
        ),
        (
            RemoteCommandIdempotencyConflictError(),
            ErrorCode.CONFLICT,
        ),
    ],
)
def test_remote_command_application_errors_use_platform_error_contract(
    error: ApplicationError,
    expected_code: ErrorCode,
) -> None:
    assert isinstance(
        error,
        ApplicationError,
    )

    assert error.code is expected_code
    assert error.message
