from __future__ import annotations

from dataclasses import dataclass, field

import pytest

import connected_vehicle.remote_command.worker_runtime as worker_runtime
from connected_vehicle.remote_command.domain import (
    RemoteCommand,
)
from connected_vehicle.remote_command.sqs_worker import (
    RemoteCommandWorkerBatchResult,
)
from enterprise_platform.config.settings import (
    Settings,
)
from enterprise_platform.messaging.sqs import (
    ReceivedEventMessage,
)


@dataclass
class FakeQueue:
    calls: list[tuple[int, int]] = field(default_factory=list)

    async def receive_events(
        self,
        *,
        max_messages: int = 10,
        wait_time_seconds: int = 0,
    ) -> tuple[ReceivedEventMessage, ...]:
        self.calls.append(
            (
                max_messages,
                wait_time_seconds,
            )
        )

        return ()

    async def close(self) -> None:
        pass

    async def delete_message(
        self,
        receipt_handle: str,
    ) -> None:
        del receipt_handle


class FakePublisher:
    async def publish(
        self,
        command: RemoteCommand,
    ) -> None:
        del command


@pytest.mark.asyncio
async def test_worker_runtime_uses_configured_queue_and_can_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = FakeQueue()
    resolved_queue_names: list[str] = []

    def fake_create_named_sqs_event_queue(
        settings: Settings,
        *,
        queue_name: str,
    ) -> FakeQueue:
        del settings

        resolved_queue_names.append(queue_name)

        return queue

    monkeypatch.setattr(
        worker_runtime,
        "create_named_sqs_event_queue",
        fake_create_named_sqs_event_queue,
    )

    settings = Settings(
        vehicle_command_queue_name=("connected-vehicle-command-runtime-test"),
        redis_key_prefix=("connected-vehicle-runtime-test"),
        _env_file=None,
    )

    runtime = worker_runtime.create_remote_command_worker_runtime(
        settings,
        object(),  # type: ignore[arg-type]
        FakePublisher(),
    )

    try:
        result = await runtime.worker.run_once()

        assert isinstance(
            result,
            RemoteCommandWorkerBatchResult,
        )

        assert result.received == 0
        assert result.processed == 0
        assert result.duplicates == 0
        assert result.in_progress == 0
        assert result.failed == 0

        assert resolved_queue_names == ["connected-vehicle-command-runtime-test"]

        assert queue.calls == [
            (
                1,
                5,
            )
        ]

    finally:
        await runtime.close()
