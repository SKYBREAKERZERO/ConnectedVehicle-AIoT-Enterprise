"""Cost-01E: SQS sender faults are terminal; throttling/unknown outcomes are not."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from enterprise_platform.messaging.envelope import EventEnvelope, create_event_envelope
from enterprise_platform.messaging.exceptions import (
    MessagePublishError,
    PermanentMessagePublishError,
)
from enterprise_platform.messaging.sqs import SQSClient, SQSEventQueue
from enterprise_platform.reliability.failure import (
    ExceptionTypeFailureClassifier,
    FailureDisposition,
)


@dataclass
class FailingSendClient:
    error: Exception
    calls: int = 0

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, str]:
        assert QueueUrl == "https://sqs.example.test/123/retry-guard"
        assert MessageBody
        self.calls += 1
        raise self.error


def _event() -> EventEnvelope:
    return create_event_envelope(
        event_id="retryguard-event-001",
        event_type="vehicle.command.requested",
        source="retryguard-contract",
        payload={"vehicle_id": "VIN-GUARD-001", "command": "lock"},
    )


def _sdk_error(code: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "synthetic"},
            "ResponseMetadata": {
                "HTTPStatusCode": 400,
                "RequestId": "test-retry-guard",
                "HostId": "test-retry-guard",
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        },
        "SendMessage",
    )


@pytest.mark.parametrize(
    "code",
    ["InvalidMessageContents", "InvalidParameterValue", "AccessDenied", "QueueDoesNotExist"],
)
@pytest.mark.asyncio
async def test_retryguard_sqs_permanent_client_error_stops_without_retry(code: str) -> None:
    client = FailingSendClient(_sdk_error(code))
    queue = SQSEventQueue(
        cast(SQSClient, client), queue_url="https://sqs.example.test/123/retry-guard"
    )
    with pytest.raises(PermanentMessagePublishError):
        await queue.send_event(_event())
    assert client.calls == 1


@pytest.mark.parametrize("code", ["RequestThrottled", "KmsDisabled", "InternalError"])
@pytest.mark.asyncio
async def test_retryguard_sqs_transient_client_error_remains_retryable(code: str) -> None:
    client = FailingSendClient(_sdk_error(code))
    queue = SQSEventQueue(
        cast(SQSClient, client), queue_url="https://sqs.example.test/123/retry-guard"
    )
    with pytest.raises(MessagePublishError):
        await queue.send_event(_event())
    assert client.calls == 1


@pytest.mark.asyncio
async def test_retryguard_sqs_unknown_timeout_retains_at_least_once_contract() -> None:
    client = FailingSendClient(ReadTimeoutError(endpoint_url="https://sqs.example.test"))
    queue = SQSEventQueue(
        cast(SQSClient, client), queue_url="https://sqs.example.test/123/retry-guard"
    )
    with pytest.raises(MessagePublishError):
        await queue.send_event(_event())
    assert client.calls == 1


def test_retryguard_classifier_never_retries_permanent_publish_rejection() -> None:
    classifier = ExceptionTypeFailureClassifier((MessagePublishError,))
    assert classifier.classify(PermanentMessagePublishError()) is FailureDisposition.NON_RETRYABLE
    assert classifier.classify(MessagePublishError()) is FailureDisposition.RETRYABLE
