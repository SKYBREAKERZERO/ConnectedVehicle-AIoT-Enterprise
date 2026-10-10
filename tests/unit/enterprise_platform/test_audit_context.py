from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from enterprise_platform.observability.context import (
    bind_observability_context,
)
from enterprise_platform.security.audit import (
    AuditContext,
    AuditOutcome,
    capture_audit_context,
    create_audit_record,
)
from enterprise_platform.security.context import (
    SecurityContext,
    bind_security_context,
)
from enterprise_platform.security.identity import (
    Principal,
    PrincipalType,
    Role,
)


def test_capture_audit_context_combines_security_and_observability() -> None:
    security_context = SecurityContext(
        principal=Principal(
            principal_id="user-001",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-001",
            roles=frozenset(
                {
                    Role.VEHICLE_OWNER,
                    Role.FLEET_OPERATOR,
                }
            ),
        )
    )

    with (
        bind_security_context(security_context),
        bind_observability_context(
            request_id="request-001",
            correlation_id="correlation-001",
            trace_id="trace-001",
        ),
    ):
        context = capture_audit_context()

    assert context.principal_id == "user-001"
    assert context.principal_type == "user"
    assert context.tenant_id == "tenant-001"
    assert context.roles == (
        "fleet_operator",
        "vehicle_owner",
    )

    assert context.request_id == "request-001"
    assert context.correlation_id == "correlation-001"
    assert context.trace_id == "trace-001"


def test_capture_audit_context_supports_unauthenticated_execution() -> None:
    with bind_observability_context(
        request_id="request-002",
        correlation_id="correlation-002",
        trace_id=None,
    ):
        context = capture_audit_context()

    assert context.principal_id is None
    assert context.principal_type is None
    assert context.tenant_id is None
    assert context.roles == ()

    assert context.request_id == "request-002"
    assert context.correlation_id == "correlation-002"
    assert context.trace_id is None


def test_create_audit_record_captures_current_context() -> None:
    security_context = SecurityContext(
        principal=Principal(
            principal_id="owner-001",
            principal_type=PrincipalType.USER,
            roles=frozenset(
                {
                    Role.VEHICLE_OWNER,
                }
            ),
        )
    )

    with (
        bind_security_context(security_context),
        bind_observability_context(
            request_id="request-003",
            correlation_id="correlation-003",
            trace_id="trace-003",
        ),
    ):
        record = create_audit_record(
            action=" vehicle.unlock ",
            resource_type=" vehicle ",
            resource_id=" VIN001 ",
            outcome=AuditOutcome.SUCCESS,
        )

    assert record.audit_id
    assert record.action == "vehicle.unlock"
    assert record.resource_type == "vehicle"
    assert record.resource_id == "VIN001"
    assert record.outcome is AuditOutcome.SUCCESS

    assert record.context.principal_id == "owner-001"
    assert record.context.request_id == "request-003"
    assert record.context.trace_id == "trace-003"

    assert record.occurred_at.tzinfo is not None


def test_create_audit_record_accepts_explicit_context_and_timestamp() -> None:
    context = AuditContext(
        principal_id="service-001",
        principal_type="service",
        tenant_id=None,
        roles=("system_service",),
        request_id=None,
        correlation_id="correlation-004",
        trace_id="trace-004",
    )

    occurred_at = datetime(
        2026,
        10,
        3,
        1,
        30,
        tzinfo=UTC,
    )

    record = create_audit_record(
        action="ota.campaign.start",
        resource_type="ota_campaign",
        resource_id="campaign-001",
        outcome=AuditOutcome.SUCCESS,
        context=context,
        occurred_at=occurred_at,
    )

    assert record.context == context
    assert record.occurred_at == occurred_at


@pytest.mark.parametrize(
    ("field_name", "kwargs"),
    [
        (
            "Audit action",
            {
                "action": "   ",
                "resource_type": "vehicle",
                "resource_id": "VIN001",
            },
        ),
        (
            "Audit resource type",
            {
                "action": "vehicle.unlock",
                "resource_type": " ",
                "resource_id": "VIN001",
            },
        ),
        (
            "Audit resource ID",
            {
                "action": "vehicle.unlock",
                "resource_type": "vehicle",
                "resource_id": "",
            },
        ),
    ],
)
def test_create_audit_record_rejects_empty_required_values(
    field_name: str,
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(
        ValueError,
        match=field_name,
    ):
        create_audit_record(
            **kwargs,
            outcome=AuditOutcome.FAILURE,
        )


def test_create_audit_record_rejects_naive_timestamp() -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        create_audit_record(
            action="vehicle.unlock",
            resource_type="vehicle",
            resource_id="VIN001",
            outcome=AuditOutcome.SUCCESS,
            occurred_at=datetime(
                2026,
                10,
                3,
                1,
                30,
            ),
        )


def test_audit_context_is_snapshot_not_live_context_reference() -> None:
    first_context = SecurityContext(
        principal=Principal(
            principal_id="first-user",
            principal_type=PrincipalType.USER,
        )
    )

    second_context = SecurityContext(
        principal=Principal(
            principal_id="second-user",
            principal_type=PrincipalType.USER,
        )
    )

    with bind_security_context(first_context):
        captured = capture_audit_context()

    with bind_security_context(second_context):
        assert capture_audit_context().principal_id == "second-user"

    assert captured.principal_id == "first-user"
