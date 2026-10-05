from __future__ import annotations

from typing import NotRequired, Protocol, TypedDict, cast
from urllib.parse import urlsplit, urlunsplit

from botocore.exceptions import BotoCoreError, ClientError

from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings
from enterprise_platform.messaging.factory import create_sqs_event_queue
from enterprise_platform.messaging.sqs import SQSEventQueue


class SQSGetQueueUrlResponse(TypedDict):
    QueueUrl: NotRequired[str]


class SQSQueueLookupClient(Protocol):
    def get_queue_url(
        self,
        *,
        QueueName: str,
    ) -> SQSGetQueueUrlResponse: ...


class SQSQueueResolutionError(RuntimeError):
    """Raised when a configured SQS queue cannot be resolved."""


def normalize_localstack_queue_url(
    queue_url: str,
    *,
    endpoint_url: str,
) -> str:
    queue_parts = urlsplit(queue_url)
    endpoint_parts = urlsplit(endpoint_url)

    if not queue_parts.path:
        raise SQSQueueResolutionError("Resolved SQS queue URL has no queue path.")

    if not endpoint_parts.scheme or not endpoint_parts.netloc:
        raise SQSQueueResolutionError("LocalStack endpoint URL is invalid.")

    return urlunsplit(
        (
            endpoint_parts.scheme,
            endpoint_parts.netloc,
            queue_parts.path,
            "",
            "",
        )
    )


def resolve_sqs_queue_url(
    settings: Settings,
    *,
    queue_name: str,
) -> str:
    normalized_queue_name = queue_name.strip()

    if not normalized_queue_name:
        raise ValueError("SQS queue name must not be empty.")

    client = cast(
        SQSQueueLookupClient,
        AWSClientFactory(settings).sqs(),
    )

    try:
        response = client.get_queue_url(
            QueueName=normalized_queue_name,
        )
    except (BotoCoreError, ClientError) as exc:
        raise SQSQueueResolutionError("Configured SQS queue could not be resolved.") from exc

    queue_url = response.get("QueueUrl")

    if not queue_url:
        raise SQSQueueResolutionError("SQS GetQueueUrl returned no queue URL.")

    if settings.cloud_runtime is CloudRuntime.LOCALSTACK:
        endpoint_url = settings.aws_endpoint_url

        if endpoint_url is None:
            raise SQSQueueResolutionError("LocalStack runtime requires an AWS endpoint URL.")

        return normalize_localstack_queue_url(
            queue_url,
            endpoint_url=endpoint_url,
        )

    return queue_url


def create_named_sqs_event_queue(
    settings: Settings,
    *,
    queue_name: str,
) -> SQSEventQueue:
    queue_url = resolve_sqs_queue_url(
        settings,
        queue_name=queue_name,
    )

    return create_sqs_event_queue(
        settings,
        queue_url=queue_url,
    )
