from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from enterprise_platform.observability.context import (
    get_observability_context,
)
from enterprise_platform.security.context import (
    get_security_context,
)


class AuditOutcome(StrEnum):
    """Stable outcome values for security-sensitive operations."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Immutable security and observability snapshot for audit records."""

    principal_id: str | None
    principal_type: str | None
    tenant_id: str | None
    roles: tuple[str, ...]

    request_id: str | None
    correlation_id: str | None
    trace_id: str | None


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Stable audit record emitted by application and platform services."""

    audit_id: str
    action: str
    resource_type: str
    resource_id: str
    outcome: AuditOutcome
    context: AuditContext
    occurred_at: datetime


def _normalize_required_value(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{field_name} must not be empty.")

    return normalized


def capture_audit_context() -> AuditContext:
    """Capture the current security and observability contexts."""

    security_context = get_security_context()
    observability_context = get_observability_context()

    if security_context is None:
        principal_id: str | None = None
        principal_type: str | None = None
        tenant_id: str | None = None
        roles: tuple[str, ...] = ()
    else:
        principal = security_context.principal

        principal_id = principal.principal_id
        principal_type = principal.principal_type.value
        tenant_id = principal.tenant_id
        roles = tuple(sorted(role.value for role in principal.roles))

    return AuditContext(
        principal_id=principal_id,
        principal_type=principal_type,
        tenant_id=tenant_id,
        roles=roles,
        request_id=observability_context.request_id,
        correlation_id=(observability_context.correlation_id),
        trace_id=observability_context.trace_id,
    )


def create_audit_record(
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: AuditOutcome,
    context: AuditContext | None = None,
    occurred_at: datetime | None = None,
) -> AuditRecord:
    """Create an immutable audit record from the current execution context."""

    normalized_action = _normalize_required_value(
        action,
        field_name="Audit action",
    )

    normalized_resource_type = _normalize_required_value(
        resource_type,
        field_name="Audit resource type",
    )

    normalized_resource_id = _normalize_required_value(
        resource_id,
        field_name="Audit resource ID",
    )

    timestamp = occurred_at if occurred_at is not None else datetime.now(UTC)

    if timestamp.tzinfo is None:
        raise ValueError("Audit timestamp must be timezone-aware.")

    return AuditRecord(
        audit_id=str(uuid4()),
        action=normalized_action,
        resource_type=normalized_resource_type,
        resource_id=normalized_resource_id,
        outcome=outcome,
        context=(context if context is not None else capture_audit_context()),
        occurred_at=timestamp,
    )
