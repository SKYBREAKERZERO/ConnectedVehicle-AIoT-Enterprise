from __future__ import annotations

import re
import ssl

import aiomqtt

from connected_vehicle.remote_command.domain import RemoteCommand
from connected_vehicle.remote_command.mqtt_publisher import MQTTRemoteCommandPublisher
from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings


class RemoteCommandPublishError(RuntimeError):
    """Broker did not acknowledge a command within the transport deadline."""


def command_topic(command: RemoteCommand) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", command.tenant_id):
        raise ValueError("Tenant ID must be a single safe MQTT topic segment.")
    return f"tenants/{command.tenant_id}/vehicles/{command.vehicle_id}/commands"


class MQTTBrokerTransport:
    """Fresh, bounded connections recover naturally after broker restarts."""

    def __init__(self, settings: Settings) -> None:
        if settings.cloud_runtime is CloudRuntime.AWS and not settings.mqtt_tls_enabled:
            raise ValueError("AWS MQTT runtime requires verified TLS.")
        if bool(settings.mqtt_cert_file) != bool(settings.mqtt_key_file):
            raise ValueError("MQTT client certificate and private key must be configured together.")
        if settings.mqtt_password is not None and not settings.mqtt_username:
            raise ValueError("MQTT password requires a username.")
        self._settings = settings
        self._tls: ssl.SSLContext | None = None
        if settings.mqtt_tls_enabled:
            self._tls = ssl.create_default_context(cafile=settings.mqtt_ca_file)
            if settings.mqtt_cert_file and settings.mqtt_key_file:
                self._tls.load_cert_chain(settings.mqtt_cert_file, settings.mqtt_key_file)

    async def publish(self, topic: str, payload: bytes, *, qos: int, retain: bool) -> None:
        settings = self._settings
        try:
            async with aiomqtt.Client(
                settings.mqtt_host,
                port=settings.mqtt_port,
                username=settings.mqtt_username,
                password=(
                    settings.mqtt_password.get_secret_value() if settings.mqtt_password else None
                ),
                tls_context=self._tls,
                timeout=settings.mqtt_timeout_seconds,
            ) as client:
                await client.publish(topic, payload=payload, qos=qos, retain=retain)
        except (aiomqtt.MqttError, OSError, TimeoutError) as exc:
            raise RemoteCommandPublishError("MQTT broker did not acknowledge the command.") from exc


class MQTTBrokerPublisher:
    """Tenant-scoped QoS 1 commands: PUBACK means broker receipt, not device execution.

    Devices deduplicate command_id and reject expired commands. Cancellation and
    errors propagate to the SQS processor so unsuccessful work is never ACKed.
    """

    def __init__(self, settings: Settings) -> None:
        self._transport = MQTTBrokerTransport(settings)

    async def publish(self, command: RemoteCommand) -> None:
        topic = command_topic(command)
        prefix = topic.rsplit("/", 2)[0]
        await MQTTRemoteCommandPublisher(self._transport, topic_prefix=prefix).publish(command)
