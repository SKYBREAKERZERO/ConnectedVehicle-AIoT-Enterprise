"""AWS IoT Core (SigV4 IAM) remote command publication; no local MQTT fallback."""

from __future__ import annotations

import asyncio
import re
from typing import Protocol

import boto3
from botocore.config import Config

from connected_vehicle.remote_command.mqtt_publisher import MQTTRemoteCommandPublisher
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings

ENDPOINT_RE = re.compile(r"[a-z0-9-]+-ats\.iot\.ap-northeast-1\.amazonaws\.com\Z")
TENANT_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class IoTDataClient(Protocol):
    def publish(self, *, topic: str, qos: int, payload: bytes, retain: bool) -> object: ...


class IoTCoreMQTTAdapter:
    """Minimal async wrapper for signed AWS IoT Data Plane publish.

    Unlike a local MQTT client, AWS publishes with the ECS task-role identity.
    Topic ACL is constrained independently by a single-tenant IAM policy.
    """

    def __init__(self, client: IoTDataClient, tenant: str) -> None:
        if not TENANT_RE.fullmatch(tenant):
            raise ValueError("AWS IoT publication requires a safe pinned tenant")
        self._client = client
        self._topic_prefix = f"tenants/{tenant}/vehicles/"

    async def publish(self, topic: str, payload: bytes, *, qos: int, retain: bool) -> object:
        if (
            not topic.startswith(self._topic_prefix)
            or not topic.endswith("/commands")
            or topic.count("/") != 4
            or "+" in topic
            or "#" in topic
            or qos != 1
            or retain
            or len(payload) > 128 * 1024
        ):
            raise ValueError("Invalid tenant-bound AWS IoT command publication")
        return await asyncio.to_thread(
            self._client.publish, topic=topic, payload=payload, qos=1, retain=False
        )


def create_aws_iot_publisher(settings: Settings) -> MQTTRemoteCommandPublisher:
    if settings.cloud_runtime is not CloudRuntime.AWS:
        raise ValueError("AWS IoT publisher requires actual AWS cloud runtime")
    if settings.aws_region != "ap-northeast-1" or settings.aws_endpoint_url:
        raise ValueError("AWS IoT publisher forbids region and LocalStack endpoint overrides")
    if not settings.database_tenant_id or not TENANT_RE.fullmatch(settings.database_tenant_id):
        raise ValueError("AWS IoT requires exact safe database tenant")
    host = settings.aws_iot_data_endpoint or ""
    if not ENDPOINT_RE.fullmatch(host):
        raise ValueError("A reviewed ATS AWS IoT Data endpoint is required")
    client = boto3.client(
        "iot-data",
        region_name=settings.aws_region,
        endpoint_url="https://" + host,
        config=Config(
            connect_timeout=settings.aws_connect_timeout_seconds,
            read_timeout=settings.aws_read_timeout_seconds,
            retries={"total_max_attempts": 1},
        ),
    )
    adapter = IoTCoreMQTTAdapter(client, settings.database_tenant_id)
    return MQTTRemoteCommandPublisher(
        adapter, topic_prefix=f"tenants/{settings.database_tenant_id}/vehicles"
    )
