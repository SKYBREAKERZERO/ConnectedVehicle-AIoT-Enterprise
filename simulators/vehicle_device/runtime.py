from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TypeVar

import aiomqtt
import httpx2 as httpx
from paho.mqtt.enums import MQTTErrorCode

from connected_vehicle.remote_command.wire_contracts import DispatchPayload
from enterprise_platform.runtime.process import termination_signals
from simulators.vehicle_device.can import VirtualCAN, command_frame, precise_command_frame
from simulators.vehicle_device.config import DeviceSettings
from simulators.vehicle_device.ownership import runtime_lock
from simulators.vehicle_device.store import CapacityError, Store, backoff

logger = logging.getLogger(__name__)
T = TypeVar("T")


class DurableMQTT(aiomqtt.Client):
    """aiomqtt 2.5.1 adapter: defer QoS1 PUBACK until the SQLite commit.

    aiomqtt has no public manual-ACK option; the pinned Paho bridge is isolated here.
    """

    def enable_manual_ack(self) -> None:
        self._client.manual_ack_set(True)

    def acknowledge(self, message: aiomqtt.Message) -> None:
        if self._client.ack(message.mid, message.qos) != MQTTErrorCode.MQTT_ERR_SUCCESS:
            raise aiomqtt.MqttError("mqtt_ack_failed")


class IncomingQueue(asyncio.Queue[T]):
    overflowed: bool = False

    def put_nowait(self, item: T) -> None:
        try:
            super().put_nowait(item)
        except asyncio.QueueFull:
            self.overflowed = True
            raise


def ingest(store: Store, settings: DeviceSettings, payload: bytes, *, retain: bool = False) -> bool:
    store.bind_identity(settings.tenant_id, str(settings.vehicle_id))
    try:
        if retain or len(payload) > 4096:
            raise ValueError("retained_or_oversized_command")
        command = DispatchPayload.model_validate_json(payload)
        if command.vehicle_id != settings.vehicle_id or command.tenant_id != settings.tenant_id:
            raise ValueError("device_identity_mismatch")
        if (
            command.created_at > datetime.now(UTC)
            or command.expires_at <= command.created_at
            or command.expires_at.timestamp() > 2**32 - 1
        ):
            raise ValueError("invalid_command_time")
        return store.accept(command)
    except ValueError:
        store.quarantine(payload, "invalid_or_conflicting_command")
        logger.warning("device_command_quarantined")
        return False


def crash_once(store: Store, settings: DeviceSettings, checkpoint: str) -> None:
    if settings.crash_after == checkpoint and store.consume_fault(checkpoint):
        os._exit(70)


async def subscribe(store: Store, settings: DeviceSettings) -> None:
    while True:
        queue: IncomingQueue[aiomqtt.Message] | None = None

        class Queue(IncomingQueue[aiomqtt.Message]):
            def __init__(self, maxsize: int) -> None:
                nonlocal queue
                super().__init__(maxsize)
                queue = self

        client = DurableMQTT(
            settings.mqtt_host,
            settings.mqtt_port,
            identifier=f"device-{settings.vehicle_id}",
            clean_session=False,
            username=settings.mqtt_username,
            password=settings.mqtt_password.get_secret_value() if settings.mqtt_password else None,
            tls_context=settings.tls_context(),
            max_queued_incoming_messages=256,
            queue_type=Queue,
            timeout=5,
        )
        client.enable_manual_ack()
        try:
            async with client:
                await client.subscribe(settings.topic, qos=1)
                logger.info("device_mqtt_ready")
                messages = client.messages.__aiter__()
                while True:
                    if queue is not None and queue.overflowed:
                        raise aiomqtt.MqttError("incoming_queue_overflow")
                    try:
                        async with asyncio.timeout(1):
                            message = await anext(messages)
                    except TimeoutError:
                        continue
                    if message.qos != 1 or str(message.topic) != settings.topic:
                        store.quarantine(message.payload, "invalid_delivery_contract")
                    else:
                        accepted = ingest(store, settings, message.payload, retain=message.retain)
                        if accepted:
                            crash_once(store, settings, "command_commit")
                    client.acknowledge(message)
        except (aiomqtt.MqttError, CapacityError) as exc:
            logger.warning("device_mqtt_reconnecting: %s", type(exc).__name__)
            await asyncio.sleep(5 if isinstance(exc, CapacityError) else backoff(2, 5))


async def dispatch(store: Store, settings: DeviceSettings, bus: VirtualCAN) -> None:
    while True:
        row = store.pending_command()
        if row is None:
            await asyncio.sleep(0.05)
            continue
        command = DispatchPayload.model_validate_json(row["payload"])
        opcode = {"lock": 1, "unlock": 2}.get(command.command_type.value)
        if opcode is None:
            store.finish(row["id"], "UNSUPPORTED_COMMAND")
            crash_once(store, settings, "result_commit")
            continue
        if row["attempts"] == 0 and command.expires_at <= datetime.now(UTC):
            store.finish(row["id"], "COMMAND_EXPIRED")
            crash_once(store, settings, "result_commit")
            continue
        # Persist intent before CAN send: a timeout never proves execution did not happen.
        store.command_retry(row["id"], row["attempts"])
        await bus.send(
            command_frame(command.command_id, opcode, int(command.expires_at.timestamp()))
            if row["can_version"] == 1
            else precise_command_frame(command.command_id, opcode, command.expires_at)
        )
        try:
            async with asyncio.timeout(0.5):
                while True:
                    response = await bus.receive()
                    if (
                        response.command_id != command.command_id
                        or response.arbitration_id != 0x180
                    ):
                        continue
                    if len(response.data) != 1 or response.data[0] not in (0, 1, 2, 3):
                        continue
                    failure = {
                        0: None,
                        1: "UNSUPPORTED_COMMAND",
                        2: "COMMAND_EXPIRED",
                        3: "COMMAND_CONFLICT",
                    }[response.data[0]]
                    store.finish(row["id"], failure)
                    crash_once(store, settings, "result_commit")
                    break
        except TimeoutError:
            logger.warning("device_can_retry")


class RetryAfterTooLong(RuntimeError):
    """Server deadline exceeds the automatic retry policy; never shorten it."""


def parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        if value.isascii() and value.isdigit():
            digits = value.lstrip("0") or "0"
            if len(digits) > 5 or int(digits) > 86400:
                raise RetryAfterTooLong
            return float(int(digits))
        deadline = parsedate_to_datetime(value)
        if deadline.tzinfo is None:
            return None
        seconds = max(0, (deadline - datetime.now(UTC)).total_seconds())
        if seconds > 86400:
            raise RetryAfterTooLong
        return seconds
    except (ValueError, TypeError, OverflowError):
        return None


async def report_once(store: Store, settings: DeviceSettings, client: httpx.AsyncClient) -> bool:
    row = store.pending_report()
    if row is None:
        return False
    status: int | None = None
    retry_after: float | None = None
    error_code: str | None = None
    try:
        # Reload each attempt so operators can rotate an expiring device identity.
        with settings.token_file.open(encoding="utf-8") as token_stream:
            raw_token = token_stream.read(8193)
        token = raw_token.strip()
        if (
            len(raw_token) > 8192
            or not token.isascii()
            or not token
            or "\n" in token
            or "\r" in token
        ):
            raise ValueError("invalid_device_token_file")
        response = await client.post(
            f"{str(settings.api_url).rstrip('/')}/vehicles/{settings.vehicle_id}/commands/"
            f"{row['command_id']}/reports",
            content=row["payload"],
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        status = response.status_code
        if 200 <= status < 300:
            event_status = json.loads(row["payload"])["status"]
            try:
                receipt = response.json()
            except ValueError:
                receipt = None
            if (
                not isinstance(receipt, dict)
                or receipt.get("command_id") != row["command_id"]
                or receipt.get("status") not in ("acknowledged", "succeeded", "failed")
                or (event_status != "acknowledged" and receipt.get("status") != event_status)
            ):
                # A malformed receipt does not prove cloud persistence. Repair/requeue explicitly.
                error_code = "HTTP_INVALID_RECEIPT"
                logger.warning("device_report_invalid_receipt")
        if status in (408, 429) or 500 <= status < 600:
            retry_after = parse_retry_after(response.headers.get("Retry-After"))
        if 300 <= status < 400:
            error_code = "HTTP_REDIRECT_BLOCKED"
    except RetryAfterTooLong:
        error_code = "HTTP_RETRY_AFTER_TOO_LONG"
        logger.warning("device_report_retry_after_blocked")
    except (httpx.HTTPError, OSError, ValueError):
        logger.warning("device_report_retry")
    store.report_result(
        row["sequence"], status, row["attempts"], retry_after, error_code=error_code
    )
    if status in (401, 403) and row["attempts"] >= 7:
        logger.error(
            "device_report_auth_exhausted event_sequence=%s "
            "requires_credential_repair_and_audited_replay",
            row["sequence"],
        )
    if status is not None and not 200 <= status < 300:
        logger.warning("device_report_http_status=%s", status)
    return True


async def report(store: Store, settings: DeviceSettings) -> None:
    async with httpx.AsyncClient(timeout=3, follow_redirects=False, trust_env=False) as client:
        while True:
            await report_once(store, settings, client)
            await asyncio.sleep(0.05)


async def _serve(settings: DeviceSettings) -> None:
    store = Store(
        settings.database,
        max_pending_commands=settings.max_pending_commands,
        max_ledger_records=settings.max_ledger_records,
        max_quarantine_records=settings.max_quarantine_records,
        min_free_bytes=settings.min_free_bytes,
    )
    try:
        store.bind_identity(settings.tenant_id, str(settings.vehicle_id))
        bus = VirtualCAN(settings.can_port, settings.gateway_port)
    except BaseException:
        store.close()
        raise
    stop = asyncio.Event()
    try:
        with termination_signals(stop):
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(subscribe(store, settings)),
                    group.create_task(dispatch(store, settings, bus)),
                    group.create_task(report(store, settings)),
                ]
                await stop.wait()
                for task in tasks:
                    task.cancel()
    finally:
        bus.close()
        store.close()
        logger.info("device_stopped")


async def serve(settings: DeviceSettings) -> None:
    with runtime_lock(settings.database, wait_seconds=1):
        await _serve(settings)
