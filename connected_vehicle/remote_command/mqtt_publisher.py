from __future__ import annotations

import json
from typing import Protocol

from connected_vehicle.remote_command.domain import (
    RemoteCommand,
    RemoteCommandStatus,
)


class MQTTClientProtocol(Protocol):
    async def publish(
        self,
        topic: str,
        payload: bytes,
        *,
        qos: int,
        retain: bool,
    ) -> object: ...


class MQTTRemoteCommandPublisher:
    """MQTT QoS 1 transport adapter for remote commands."""

    def __init__(
        self,
        client: MQTTClientProtocol,
        *,
        topic_prefix: str = "vehicles",
    ) -> None:
        prefix = topic_prefix.strip("/")

        if not prefix or "+" in prefix or "#" in prefix or "//" in prefix or "\x00" in prefix:
            raise ValueError("Invalid MQTT topic prefix.")

        self._client = client
        self._topic_prefix = prefix

    async def publish(self, command: RemoteCommand) -> None:
        if command.status is not RemoteCommandStatus.DISPATCHING:
            raise ValueError("MQTT publication requires DISPATCHING status.")

        topic = f"{self._topic_prefix}/{command.vehicle_id.value}/commands"

        payload = {
            "schema_version": "1.0",
            "command_id": command.id.value,
            "vehicle_id": command.vehicle_id.value,
            "tenant_id": command.tenant_id,
            "command_type": command.command_type.value,
            "created_at": command.created_at.isoformat(),
            "expires_at": command.expires_at.isoformat(),
        }

        encoded = json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        await self._client.publish(
            topic,
            encoded,
            qos=1,
            retain=False,
        )
