"""Test-only socket and abrupt-process faults; never imported by runtime packages."""

from __future__ import annotations

import asyncio
import os
import struct
from contextlib import suppress
from pathlib import Path
from uuid import UUID

import boto3
from pydantic import SecretStr

from connected_vehicle.remote_command.dispatch_service import RemoteCommandDispatchService
from connected_vehicle.remote_command.domain import RemoteCommand
from connected_vehicle.remote_command.event_handler import RemoteCommandRequestedEventHandler
from connected_vehicle.vehicle.persistence.models import VehicleModel
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.outbox_store import SQLAlchemyOutboxStore
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.messaging.serialization import deserialize_event_envelope
from simulators.body_ecu.service import BodyStore
from simulators.vehicle_device.can import precise_command_frame


class CommitResponseDropper:
    """Drop the actual COMMIT CommandComplete response after PostgreSQL sends it.

    SSL must be disabled on this isolated loopback test connection. The backend
    has completed COMMIT; no simulated session.commit implementation is used.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self.dropped = asyncio.Event()
        self.tasks: set[asyncio.Task[None]] = set()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        upstream: asyncio.StreamWriter | None = None
        forwarding: asyncio.Task[None] | None = None
        try:
            backend, upstream = await asyncio.open_connection(self.host, self.port)

            async def forward() -> None:
                assert upstream is not None
                try:
                    while block := await reader.read(65536):
                        upstream.write(block)
                        await upstream.drain()
                finally:
                    upstream.close()

            forwarding = asyncio.create_task(forward())
            while True:
                kind = await backend.readexactly(1)
                size = await backend.readexactly(4)
                length = struct.unpack("!I", size)[0]
                if not 4 <= length <= 16 * 1024 * 1024:
                    raise ValueError("Invalid PostgreSQL test frame")
                payload = await backend.readexactly(length - 4)
                if kind == b"C" and payload == b"COMMIT\0" and not self.dropped.is_set():
                    self.dropped.set()
                    return
                writer.write(kind + size + payload)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            if forwarding is not None:
                forwarding.cancel()
                await asyncio.gather(forwarding, return_exceptions=True)
            for stream in (upstream, writer):
                if stream is not None:
                    stream.close()
                    with suppress(OSError, TimeoutError):
                        await asyncio.wait_for(stream.wait_closed(), 1)
            self.tasks.discard(task)

    async def close(self) -> None:
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)


async def crash_outbox() -> None:
    settings = Settings.model_construct(
        database_host="127.0.0.1",
        database_port=int(os.environ["DAY16_DB_PORT"]),
        database_name="postgres",
        database_username=os.environ["DAY16_DB_USER"],
        database_password=SecretStr(os.environ["DAY16_DB_PASSWORD"]),
    )
    engine = create_database_engine(settings)
    assert VehicleModel.__tablename__ == "vehicles"  # Register command FK metadata in this process.
    if os.environ.get("DAY16_CRASH_POINT") == "after_execution":

        class Publisher:
            async def publish(self, command: RemoteCommand) -> None:
                body = BodyStore(Path(os.environ["DAY16_BODY_PATH"]))
                frame = precise_command_frame(
                    UUID(command.id.value),
                    1,
                    command.expires_at,
                )
                assert body.execute(frame).data == b"\x00"
                # SQLite commit is durable, but SENT and SQS acknowledgement have not happened.
                os._exit(87)

        handler = RemoteCommandRequestedEventHandler(
            RemoteCommandDispatchService(
                create_session_factory(engine),
                Publisher(),
            )
        )
        await handler(deserialize_event_envelope(os.environ["DAY16_MESSAGE"]))
        raise AssertionError("Execution crash checkpoint was not reached")
    claimed = await SQLAlchemyOutboxStore(create_session_factory(engine)).claim_batch(
        batch_size=1,
        lease_seconds=1,
    )
    assert len(claimed) == 1
    if os.environ["DAY16_CRASH_POINT"] == "before_send":
        os._exit(85)
    client = boto3.client(
        "sqs",
        endpoint_url=os.environ["DAY16_ENDPOINT"],
        region_name="ap-northeast-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    client.send_message(QueueUrl=os.environ["DAY16_QUEUE_URL"], MessageBody=claimed[0].event_body)
    # Abrupt process termination: no finally, rollback, mark_published or graceful drain.
    os._exit(86)


if __name__ == "__main__":
    asyncio.run(crash_outbox())
