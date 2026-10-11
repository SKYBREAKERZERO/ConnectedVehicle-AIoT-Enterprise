from __future__ import annotations

from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from connected_vehicle.remote_command.event_handler import dispatch_idempotency_key
from enterprise_platform.messaging.exceptions import InvalidMessageError
from enterprise_platform.messaging.reliable_sqs_consumer import ReliableSQSEventProcessor
from enterprise_platform.messaging.sqs import ReceivedEventMessage
from enterprise_platform.reliability.idempotency import IdempotencyDecision
from tests.unit.connected_vehicle.test_remote_command_event_handler import create_requested_event


@pytest.mark.asyncio
async def test_forged_tenant_cannot_hit_completed_cache_before_validation() -> None:
    event = create_requested_event()
    forged = replace(event, payload=dict(event.payload) | {"tenant_id": "tenant-b"})
    valid_key = dispatch_idempotency_key(event)
    assert dispatch_idempotency_key(forged) != valid_key
    coordinator = AsyncMock()
    coordinator.begin.side_effect = lambda key: (
        IdempotencyDecision.COMPLETED if key == valid_key else IdempotencyDecision.ACQUIRED
    )
    acknowledger = AsyncMock()
    handler = AsyncMock(side_effect=InvalidMessageError())
    processor = ReliableSQSEventProcessor(
        acknowledger=acknowledger, idempotency=coordinator, key_for_event=dispatch_idempotency_key
    )
    with pytest.raises(InvalidMessageError):
        await processor.process(ReceivedEventMessage("forged", "receipt", forged), handler=handler)
    handler.assert_awaited_once_with(forged)
    acknowledger.delete_message.assert_not_awaited()
    coordinator.complete.assert_not_awaited()
    coordinator.abandon.assert_awaited_once_with(dispatch_idempotency_key(forged))


def test_trace_metadata_does_not_change_tenant_cache_key() -> None:
    event = create_requested_event()
    assert dispatch_idempotency_key(event) == dispatch_idempotency_key(
        replace(event, trace_id="new")
    )


@pytest.mark.asyncio
async def test_database_scope_cannot_override_authenticated_tenant() -> None:
    from enterprise_platform.database.tenant import set_tenant_scope
    from enterprise_platform.security.context import SecurityContext, bind_security_context
    from enterprise_platform.security.exceptions import AuthorizationDeniedError
    from enterprise_platform.security.identity import Principal, PrincipalType

    session = AsyncMock()
    context = SecurityContext(Principal("operator", PrincipalType.USER, tenant_id="tenant-a"))
    with bind_security_context(context), pytest.raises(AuthorizationDeniedError):
        await set_tenant_scope(session, "tenant-b")
    session.execute.assert_not_awaited()


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-b"),
        ("vehicle_id", "00000000-0000-0000-0000-000000000001"),
        ("command_type", "unlock"),
    ],
)
def test_cache_fingerprint_separates_tenant_vehicle_and_content(field: str, value: str) -> None:
    event = create_requested_event()
    changed = replace(event, payload=dict(event.payload) | {field: value})
    assert dispatch_idempotency_key(changed) != dispatch_idempotency_key(event)
