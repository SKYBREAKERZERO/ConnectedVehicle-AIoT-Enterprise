from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorBodyContract(BaseModel):
    """Stable public HTTP error payload."""

    model_config = ConfigDict(
        extra="forbid",
    )

    code: str
    message: str
    request_id: str | None
    correlation_id: str | None


class ErrorResponseContract(BaseModel):
    """Stable public HTTP error response envelope."""

    model_config = ConfigDict(
        extra="forbid",
    )

    error: ErrorBodyContract
