from __future__ import annotations

import pytest

from enterprise_platform.errors import (
    ApplicationError,
    ConflictError,
    DependencyTimeoutError,
    DependencyUnavailableError,
    ErrorCode,
    InvalidRequestError,
    ResourceNotFoundError,
)


def test_application_error_exposes_stable_code_and_message() -> None:
    error = ApplicationError(
        code=ErrorCode.INVALID_REQUEST,
        message="Invalid vehicle identifier.",
    )

    assert error.code is ErrorCode.INVALID_REQUEST
    assert error.message == "Invalid vehicle identifier."
    assert str(error) == "Invalid vehicle identifier."


def test_application_error_rejects_empty_message() -> None:
    with pytest.raises(
        ValueError,
        match="Application error message must not be empty",
    ):
        ApplicationError(
            code=ErrorCode.INVALID_REQUEST,
            message="   ",
        )


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (
            InvalidRequestError(),
            ErrorCode.INVALID_REQUEST,
        ),
        (
            ResourceNotFoundError(),
            ErrorCode.RESOURCE_NOT_FOUND,
        ),
        (
            ConflictError(),
            ErrorCode.CONFLICT,
        ),
        (
            DependencyUnavailableError(),
            ErrorCode.DEPENDENCY_UNAVAILABLE,
        ),
        (
            DependencyTimeoutError(),
            ErrorCode.DEPENDENCY_TIMEOUT,
        ),
    ],
)
def test_specialized_errors_use_expected_code(
    error: ApplicationError,
    expected_code: ErrorCode,
) -> None:
    assert error.code is expected_code
    assert error.message
