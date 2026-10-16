from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from database.credential_audit import save_checkpoint, verify_archive_chain
from database.credential_rotation import rotate
from enterprise_platform.database.recovery import CommitOutcomeUnknown
from enterprise_platform.errors.handlers import register_exception_handlers
from tests.unit.test_credential_rotation import candidates, setup


@pytest.mark.parametrize("point", ["fsync", "link", "checkpoint"])
async def test_audit_segment_interruption_preserves_confirmed_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    settings, targets, service, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), service, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    while len(record["events"]) < 64:
        save_checkpoint(path, record)
    before = path.read_bytes()
    snapshot = deepcopy(record)

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("injected storage interruption")

    with monkeypatch.context() as patch:
        target = {"fsync": "os.fsync", "link": "os.link", "checkpoint": "os.replace"}[point]
        patch.setattr("database.credential_audit." + target, fail)
        with pytest.raises(OSError):
            save_checkpoint(path, record)
    assert path.read_bytes() == before and record == snapshot
    assert verify_archive_chain(path, record) == 0
    # Checkpoint failure can leave a fully written, unreferenced immutable segment;
    # retry publishes the same valid history without reading temporary fragments.
    save_checkpoint(path, record)
    assert verify_archive_chain(path, record) == 1
    assert len(list((tmp_path / "audit").glob("*.json"))) >= 1
    assert all(item.suffix == ".json" for item in (tmp_path / "audit").iterdir())


def test_unknown_commit_http_response_preserves_retry_identity_and_hides_details() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/command")
    async def command() -> None:
        raise CommitOutcomeUnknown("password=private db-host=internal")

    response = TestClient(app).post("/command")
    assert response.status_code == 503
    assert "same idempotency key" in response.text
    assert "private" not in response.text and "internal" not in response.text


async def test_unknown_commit_does_not_allow_same_key_different_parameters() -> None:
    from connected_vehicle.remote_command.application_errors import (
        RemoteCommandIdempotencyConflictError,
    )
    from connected_vehicle.remote_command.domain import RemoteCommand, RemoteCommandType
    from connected_vehicle.remote_command.service import IssueRemoteCommandService
    from connected_vehicle.vehicle import VehicleId

    existing = RemoteCommand.request(
        vehicle_id=VehicleId.new(),
        tenant_id="tenant-a",
        command_type=RemoteCommandType.LOCK,
        idempotency_key="operation-1",
    )
    service = IssueRemoteCommandService(AsyncMock())
    execute = AsyncMock(side_effect=CommitOutcomeUnknown())
    lookup = AsyncMock(return_value=existing)
    service._issue_with_conflict_resolution = execute  # type: ignore[method-assign]
    service._find_existing_after_conflict = lookup  # type: ignore[method-assign]
    with pytest.raises(RemoteCommandIdempotencyConflictError):
        await service.issue(
            vehicle_id=existing.vehicle_id,
            tenant_id="tenant-a",
            command_type=RemoteCommandType.UNLOCK,
            idempotency_key="operation-1",
        )
    execute.assert_awaited_once()
