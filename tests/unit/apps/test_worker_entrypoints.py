from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from apps.outbox_worker.main import resolve_dispatcher
from apps.remote_command_worker.main import resolve_worker


class Holder:
    def __init__(self, attribute: str, value: object) -> None:
        setattr(self, attribute, value)


def test_outbox_entrypoint_accepts_dispatcher_or_holder() -> None:
    dispatcher = AsyncMock(spec=["dispatch_batch"])
    assert resolve_dispatcher(dispatcher) is dispatcher
    assert resolve_dispatcher(Holder("dispatcher", dispatcher)) is dispatcher


def test_outbox_entrypoint_rejects_incompatible_runtime() -> None:
    with pytest.raises(TypeError, match="dispatch_batch"):
        resolve_dispatcher(object())


def test_remote_entrypoint_accepts_worker_or_holder() -> None:
    worker = AsyncMock(spec=["run_once"])
    assert resolve_worker(worker) is worker
    assert resolve_worker(Holder("worker", worker)) is worker


def test_remote_entrypoint_rejects_incompatible_runtime() -> None:
    with pytest.raises(TypeError, match="run_once"):
        resolve_worker(object())
