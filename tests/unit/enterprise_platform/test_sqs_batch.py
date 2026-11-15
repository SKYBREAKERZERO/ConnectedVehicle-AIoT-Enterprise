"""SQS SendMessageBatch contract: identity mapping, partial failure, and limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import pytest

from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.exceptions import MessagePublishError
from enterprise_platform.messaging.sqs import (
    SQSBatchSendResponse,
    SQSClient,
    SQSEventQueue,
)


@dataclass
class FakeBatchClient:
    calls: list[list[dict[str, str]]] = field(default_factory=list)
    fail_response: bool = False
    partial: bool = False
    malformed: bool = False

    def send_message_batch(
        self, *, QueueUrl: str, Entries: list[dict[str, str]]
    ) -> SQSBatchSendResponse:
        assert QueueUrl == "https://sqs.example.test/123/test"
        self.calls.append(Entries)
        if self.fail_response:
            raise MessagePublishError()
        if self.malformed:
            return {"Successful": [{"Id": "unexpected", "MessageId": "bad"}]}
        result: SQSBatchSendResponse = {"Successful": [], "Failed": []}
        for entry in reversed(Entries):
            if self.partial and entry["Id"] == "1":
                result["Failed"].append(
                    {"Id": entry["Id"], "Code": "Throttling", "SenderFault": False}
                )
            elif self.partial and entry["Id"] == "2":
                result["Failed"].append(
                    {"Id": entry["Id"], "Code": "InvalidMessage", "SenderFault": True}
                )
            else:
                result["Successful"].append(
                    {"Id": entry["Id"], "MessageId": "message-" + entry["Id"]}
                )
        return result


def make_events(count: int) -> tuple[EventEnvelope, ...]:
    return tuple(
        create_event_envelope(
            event_id=f"test-batch-{i:04}",
            event_type="vehicle.command.requested",
            source="batch-contract-test",
            payload={"command": "lock", "vehicle_id": "VIN-UNIT"},
        )
        for i in range(count)
    )


@pytest.mark.asyncio
async def test_cost01c_sqs_batch_20_events_two_api_calls() -> None:
    fake = FakeBatchClient()
    queue = SQSEventQueue(
        cast(SQSClient, fake), queue_url="https://sqs.example.test/123/test"
    )
    outcomes = await queue.send_events_batch(make_events(20))
    assert len(fake.calls) == 2
    assert [len(batch) for batch in fake.calls] == [10, 10]
    assert len(outcomes) == 20
    assert [item.event_id for item in outcomes] == [
        f"test-batch-{i:04}" for i in range(20)
    ]
    assert all(result.status == "sent" for result in outcomes)


@pytest.mark.asyncio
async def test_cost01c_http200_partial_failures_are_mapped_by_id() -> None:
    fake = FakeBatchClient(partial=True)
    queue = SQSEventQueue(
        cast(SQSClient, fake), queue_url="https://sqs.example.test/123/test"
    )
    outcomes = await queue.send_events_batch(make_events(4))
    assert [outcome.status for outcome in outcomes] == [
        "sent",
        "retryable",
        "permanent",
        "sent",
    ]
    assert outcomes[1].failure_code == "Throttling"
    assert outcomes[2].failure_code == "InvalidMessage"


@pytest.mark.asyncio
async def test_cost01c_invalid_or_missing_batch_response_fails_closed() -> None:
    fake = FakeBatchClient(malformed=True)
    queue = SQSEventQueue(
        cast(SQSClient, fake), queue_url="https://sqs.example.test/123/test"
    )
    with pytest.raises(MessagePublishError):
        await queue.send_events_batch(make_events(3))


@pytest.mark.asyncio
async def test_cost01c_fifo_without_group_contract_is_rejected() -> None:
    fake = FakeBatchClient()
    queue = SQSEventQueue(
        cast(SQSClient, fake),
        queue_url="https://sqs.example.test/123/test.fifo",
    )
    with pytest.raises(ValueError, match="FIFO"):
        await queue.send_events_batch(make_events(2))
    assert fake.calls == []
