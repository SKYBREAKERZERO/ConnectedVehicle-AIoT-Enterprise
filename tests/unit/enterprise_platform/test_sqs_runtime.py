from __future__ import annotations

from typing import cast

import pytest

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.messaging.sqs_runtime import (
    SQSGetQueueUrlResponse,
    SQSQueueLookupClient,
    SQSQueueResolutionError,
    create_named_sqs_event_queue,
    normalize_localstack_queue_url,
    resolve_sqs_queue_url,
)
from tests.settings_helpers import isolated_settings


class FakeSQSLookupClient:
    def __init__(
        self,
        response: SQSGetQueueUrlResponse,
    ) -> None:
        self.response = response
        self.queue_names: list[str] = []

    def get_queue_url(
        self,
        *,
        QueueName: str,
    ) -> SQSGetQueueUrlResponse:
        self.queue_names.append(QueueName)

        return self.response


def install_fake_sqs_client(
    monkeypatch: pytest.MonkeyPatch,
    client: FakeSQSLookupClient,
) -> None:
    def fake_sqs(
        self: AWSClientFactory,
    ) -> SQSQueueLookupClient:
        del self

        return cast(
            SQSQueueLookupClient,
            client,
        )

    monkeypatch.setattr(
        AWSClientFactory,
        "sqs",
        fake_sqs,
    )


def test_normalize_localstack_queue_url_uses_host_endpoint() -> None:
    result = normalize_localstack_queue_url(
        ("http://localstack:4566/000000000000/connected-vehicle-command"),
        endpoint_url="http://localhost:14566",
    )

    assert result == ("http://localhost:14566/000000000000/connected-vehicle-command")


def test_resolve_sqs_queue_url_uses_configured_queue_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeSQSLookupClient(
        {"QueueUrl": ("http://localstack:4566/000000000000/connected-vehicle-command")}
    )

    install_fake_sqs_client(
        monkeypatch,
        client,
    )

    settings = isolated_settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_endpoint_url="http://localhost:14566",
        _env_file=None,
    )

    queue_url = resolve_sqs_queue_url(
        settings,
        queue_name="connected-vehicle-command",
    )

    assert client.queue_names == ["connected-vehicle-command"]

    assert queue_url == ("http://localhost:14566/000000000000/connected-vehicle-command")


def test_resolve_sqs_queue_url_rejects_missing_queue_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeSQSLookupClient({})

    install_fake_sqs_client(
        monkeypatch,
        client,
    )

    settings = isolated_settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_endpoint_url="http://localhost:14566",
        _env_file=None,
    )

    with pytest.raises(
        SQSQueueResolutionError,
        match="returned no queue URL",
    ):
        resolve_sqs_queue_url(
            settings,
            queue_name="connected-vehicle-command",
        )


def test_create_named_sqs_event_queue_uses_resolved_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeSQSLookupClient(
        {"QueueUrl": ("http://localstack:4566/000000000000/connected-vehicle-command")}
    )

    install_fake_sqs_client(
        monkeypatch,
        client,
    )

    settings = isolated_settings(
        cloud_runtime=CloudRuntime.LOCALSTACK,
        aws_endpoint_url="http://localhost:14566",
        _env_file=None,
    )

    queue = create_named_sqs_event_queue(
        settings,
        queue_name="connected-vehicle-command",
    )

    assert queue.queue_url == ("http://localhost:14566/000000000000/connected-vehicle-command")
