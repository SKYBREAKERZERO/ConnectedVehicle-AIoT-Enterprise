from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import aiomqtt
import pytest

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandStatus,
    RemoteCommandType,
)
from connected_vehicle.remote_command.mqtt_runtime import (
    MQTTBrokerPublisher,
    RemoteCommandPublishError,
    command_topic,
)
from connected_vehicle.vehicle import VehicleId
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings


def command(tenant: str = "tenant-1") -> RemoteCommand:
    issued = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id=tenant,
        command_type=RemoteCommandType.LOCK,
        idempotency_key="mqtt-test",
    )

    return issued.transition_to(RemoteCommandStatus.QUEUED).transition_to(
        RemoteCommandStatus.DISPATCHING
    )


async def test_waits_for_qos1_ack_and_closes_transport() -> None:
    transport = AsyncMock()
    transport.__aenter__.return_value = transport
    issued = command()
    with patch(
        "connected_vehicle.remote_command.mqtt_runtime.aiomqtt.Client", return_value=transport
    ):
        await MQTTBrokerPublisher(Settings.model_construct()).publish(issued)
    transport.publish.assert_awaited_once()
    call = transport.publish.call_args
    assert call.args[0] == command_topic(issued)
    assert call.kwargs["qos"] == 1 and call.kwargs["retain"] is False
    payload = json.loads(call.kwargs["payload"])
    assert payload["command_id"] == str(issued.id)
    assert payload["expires_at"] == issued.expires_at.isoformat()
    transport.__aexit__.assert_awaited_once()


@pytest.mark.parametrize("error", [aiomqtt.MqttError("failed"), OSError("failed"), TimeoutError()])
async def test_transport_failure_is_not_success(error: Exception) -> None:
    transport = AsyncMock()
    transport.__aenter__.return_value = transport
    transport.publish.side_effect = error
    with (
        patch(
            "connected_vehicle.remote_command.mqtt_runtime.aiomqtt.Client", return_value=transport
        ),
        pytest.raises(RemoteCommandPublishError),
    ):
        await MQTTBrokerPublisher(Settings.model_construct()).publish(command())
    transport.__aexit__.assert_awaited_once()


async def test_cancellation_propagates_and_closes_transport() -> None:
    transport = AsyncMock()
    transport.__aenter__.return_value = transport
    transport.publish.side_effect = asyncio.CancelledError()
    with (
        patch(
            "connected_vehicle.remote_command.mqtt_runtime.aiomqtt.Client", return_value=transport
        ),
        pytest.raises(asyncio.CancelledError),
    ):
        await MQTTBrokerPublisher(Settings.model_construct()).publish(command())
    transport.__aexit__.assert_awaited_once()


@pytest.mark.parametrize("tenant", ["a/b", "a+", "a#", "a\x00", "a.b"])
def test_tenant_cannot_inject_mqtt_topic(tenant: str) -> None:
    with pytest.raises(ValueError):
        command_topic(command(tenant))


def test_aws_requires_verified_tls() -> None:
    with pytest.raises(ValueError, match="verified TLS"):
        MQTTBrokerPublisher(Settings.model_construct(cloud_runtime=CloudRuntime.AWS))
    adapter = MQTTBrokerPublisher(
        Settings.model_construct(cloud_runtime=CloudRuntime.AWS, mqtt_tls_enabled=True)
    )
    assert adapter is not None
