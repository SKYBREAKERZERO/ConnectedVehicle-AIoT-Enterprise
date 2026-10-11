from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import subprocess
import sys
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import aiomqtt
import httpx2 as httpx
import pytest
from pydantic import ValidationError

from connected_vehicle.remote_command.domain import RemoteCommandType
from connected_vehicle.remote_command.wire_contracts import DispatchPayload
from simulators.body_ecu.service import BodyStore
from simulators.gateway.service import GatewayStore
from simulators.vehicle_device.can import Frame, VirtualCAN, command_frame
from simulators.vehicle_device.config import DeviceSettings
from simulators.vehicle_device.runtime import (
    DurableMQTT,
    IncomingQueue,
    dispatch,
    ingest,
    parse_retry_after,
    report_once,
)
from simulators.vehicle_device.store import CapacityError, Store, backoff

ROOT = Path(__file__).resolve().parents[2]


def settings(tmp_path: Path) -> DeviceSettings:
    token = tmp_path / "token"
    token.write_text("signed-device-token", encoding="utf-8")
    return DeviceSettings(
        tenant_id="tenant",
        vehicle_id=uuid4(),
        api_url="http://127.0.0.1:8000",  # type: ignore[arg-type]
        token_file=token,
        database=tmp_path / "gateway.sqlite",
        allow_insecure_local=True,
    )


def payload(config: DeviceSettings, command_id: UUID | None = None) -> DispatchPayload:
    now = datetime.now(UTC)
    return DispatchPayload.model_validate(
        {
            "schema_version": "1.0",
            "tenant_id": config.tenant_id,
            "vehicle_id": config.vehicle_id,
            "command_id": command_id or uuid4(),
            "command_type": "lock",
            "created_at": now,
            "expires_at": now + timedelta(seconds=60),
        }
    )


def test_ack_and_result_survive_restart_order_and_deduplicate(tmp_path: Path) -> None:
    config = settings(tmp_path)
    command = payload(config)
    store = Store(config.database)
    assert ingest(store, config, command.model_dump_json().encode())
    ack = store.pending_report()
    assert ack is not None
    event_id = json.loads(ack["payload"])["event_id"]
    store.close()
    store = Store(config.database)
    try:
        assert not ingest(store, config, command.model_dump_json().encode())
        store.finish(str(command.command_id))
        store.finish(str(command.command_id))
        ack = store.pending_report()
        assert ack is not None and json.loads(ack["payload"])["event_id"] == event_id
        assert len(store.reconcile()["reports"]) == 2  # type: ignore[arg-type]
        store.report_result(ack["sequence"], 409, 0)
        assert store.pending_report() is None
        store.requeue_report(
            tenant_id=config.tenant_id,
            vehicle_id=str(config.vehicle_id),
            event_id=event_id,
            operation_id=str(uuid4()),
            actor="test-operator",
            reason="conflict reconciled",
        )
        ack = store.pending_report()
        assert ack is not None
        store.report_result(ack["sequence"], 204, 1)
        result = store.pending_report()
        assert result is not None and json.loads(result["payload"])["status"] == "succeeded"
    finally:
        store.close()


def test_conflicting_and_foreign_commands_are_durably_quarantined(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    try:
        assert ingest(store, config, command.model_dump_json().encode())
        conflicting = command.model_copy(update={"command_type": RemoteCommandType.UNLOCK})
        assert not ingest(store, config, conflicting.model_dump_json().encode())
        foreign = command.model_copy(update={"vehicle_id": uuid4()})
        assert not ingest(store, config, foreign.model_dump_json().encode())
        assert not ingest(store, config, b"not-json")
        assert not ingest(store, config, command.model_dump_json().encode(), retain=True)
        assert store.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 1
        assert store.db.execute("SELECT count(*) FROM quarantine").fetchone()[0] == 4
    finally:
        store.close()


def test_body_execution_and_cached_result_are_atomic_after_reopen(tmp_path: Path) -> None:
    database = tmp_path / "body.sqlite"
    frame = command_frame(uuid4(), 1, int((datetime.now(UTC) + timedelta(seconds=60)).timestamp()))
    body = BodyStore(database)
    assert body.execute(frame).data == b"\x00"
    body.close()
    body = BodyStore(database)
    try:
        assert body.execute(frame).data == b"\x00"
        assert body.db.execute("SELECT locked FROM body").fetchone()[0] == 1
        assert body.db.execute("SELECT count(*) FROM executions").fetchone()[0] == 1
        assert body.execute(command_frame(frame.command_id, 2, 1)).data == b"\x03"
        assert body.db.execute("SELECT locked FROM body").fetchone()[0] == 1
        assert body.execute(command_frame(uuid4(), 2, 1)).data == b"\x02"
        assert body.execute(command_frame(uuid4(), 99, 2**32 - 1)).data == b"\x01"
    finally:
        body.close()


@pytest.mark.parametrize("status", [503, 429, 401, 403, None])
async def test_report_transport_retry_keeps_identity_and_order(
    tmp_path: Path, status: int | None
) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.accept(command)
    store.finish(str(command.command_id))
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            if status is None:
                raise httpx.ReadTimeout("response lost", request=request)
            return httpx.Response(status)
        return httpx.Response(
            200,
            json={
                "command_id": str(command.command_id),
                "status": json.loads(request.content)["status"],
            },
        )

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert await report_once(store, config, client)
            store.db.execute("UPDATE reports SET next_attempt=0")
            store.db.commit()
            config.token_file.write_text("rotated-token", encoding="utf-8")
            assert await report_once(store, config, client)
            assert requests[0].content == requests[1].content
            assert requests[1].headers["Authorization"] == "Bearer rotated-token"
            assert await report_once(store, config, client)
            assert json.loads(requests[2].content)["status"] == "succeeded"
    finally:
        store.close()


def test_tls_and_loopback_contract(tmp_path: Path) -> None:
    config = settings(tmp_path)
    raw = config.model_dump()
    raw["mqtt_host"] = "example.com"
    with pytest.raises(ValidationError):
        DeviceSettings.model_validate(raw)
    raw = config.model_dump()
    raw["allow_insecure_local"] = False
    with pytest.raises(ValidationError):
        DeviceSettings.model_validate(raw)
    raw = config.model_dump()
    raw["tenant_id"] = "tenant/#"
    with pytest.raises(ValidationError):
        DeviceSettings.model_validate(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b"x",
        b"x" * 257,
        b'{"command_id":null,"arbitration_id":256,"data":"01"}',
        b'{"command_id":"invalid","arbitration_id":256,"data":"01"}',
    ],
)
def test_malformed_virtual_can(raw: bytes) -> None:
    with pytest.raises(ValueError):
        Frame.decode(raw)


async def test_manual_ack_bridge_and_bounded_queue() -> None:
    client = DurableMQTT("127.0.0.1", identifier="test-device", clean_session=False)
    client.enable_manual_ack()
    assert client._client._manual_ack  # Pin upgrade regression: never auto-ACK before SQLite.
    queue: IncomingQueue[aiomqtt.Message] = IncomingQueue(1)
    message = aiomqtt.Message("test", b"x", 1, False, 1, None)
    queue.put_nowait(message)
    with pytest.raises(asyncio.QueueFull):
        queue.put_nowait(message)
    assert queue.overflowed


def udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_independent_body_process_crash_commit_and_replay(tmp_path: Path) -> None:
    gateway_port, body_port = udp_port(), udp_port()
    database = tmp_path / "body.sqlite"
    command = [
        sys.executable,
        "-m",
        "simulators.body_ecu",
        "--database",
        str(database),
        "--port",
        str(body_port),
        "--gateway-port",
        str(gateway_port),
        "--crash-after-execution",
    ]
    bus = VirtualCAN(gateway_port, body_port)
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    frame = command_frame(uuid4(), 1, 2**32 - 1)
    try:
        for _ in range(80):
            await bus.send(frame)
            await asyncio.sleep(0.05)
            if process.poll() is not None:
                break
        assert process.poll() == 71
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT locked FROM body").fetchone()[0] == 1
        process = subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        async with asyncio.timeout(5):
            while True:
                await bus.send(frame)
                try:
                    async with asyncio.timeout(0.1):
                        result = await bus.receive()
                    assert result.command_id == frame.command_id and result.data == b"\x00"
                    break
                except TimeoutError:
                    continue
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT count(*) FROM executions").fetchone()[0] == 1
    finally:
        process.kill()
        process.wait(timeout=5)
        bus.close()


def test_gateway_route_ledger_recovers_and_rejects_conflicting_results(tmp_path: Path) -> None:
    database = tmp_path / "gateway.sqlite"
    frame = command_frame(uuid4(), 1, 2**32 - 1)
    gateway = GatewayStore(database)
    assert gateway.accept(frame) == (True, None)
    gateway.close()
    gateway = GatewayStore(database)
    try:
        assert gateway.pending() == [frame]
        assert gateway.accept(frame) == (False, None)
        response = Frame(frame.command_id, 0x180, b"\x00")
        assert gateway.finish(response)
        assert gateway.pending() == []
        assert gateway.accept(frame) == (False, response)
        assert not gateway.finish(Frame(uuid4(), 0x180, b"\x00"))
        assert not gateway.finish(Frame(frame.command_id, 0x180, b"\x02"))
        conflict = command_frame(frame.command_id, 2, 2**32 - 1)
        assert gateway.accept(conflict) == (False, Frame(frame.command_id, 0x180, b"\x03"))
        assert gateway.reconcile()["routes"] == [
            {
                "command_id": str(frame.command_id),
                "state": "completed",
                "result_code": 0,
                "attempts": 1,
            }
        ]
    finally:
        gateway.close()


@pytest.mark.parametrize("already_attempted", [False, True])
async def test_expired_command_does_not_turn_unknown_execution_into_failure(
    tmp_path: Path, already_attempted: bool
) -> None:
    config = settings(tmp_path).model_copy(
        update={"can_port": udp_port(), "gateway_port": udp_port()}
    )
    command = payload(config).model_copy(
        update={
            "created_at": datetime.now(UTC) - timedelta(seconds=10),
            "expires_at": datetime.now(UTC) - timedelta(seconds=1),
        }
    )
    store = Store(config.database)
    store.accept(command)
    if already_attempted:
        store.db.execute("UPDATE commands SET attempts=1")
        store.db.commit()
    bus = VirtualCAN(config.can_port, config.gateway_port)
    task = asyncio.create_task(dispatch(store, config, bus))
    try:
        async with asyncio.timeout(2):
            while True:
                row = store.db.execute("SELECT state,attempts FROM commands").fetchone()
                if (already_attempted and row["attempts"] > 1) or row["state"] == "failed":
                    break
                await asyncio.sleep(0.01)
        assert row["state"] == ("pending" if already_attempted else "failed")
        assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == (
            1 if already_attempted else 2
        )
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        bus.close()
        store.close()


def test_pending_lock_blocks_later_unlock_during_backoff(tmp_path: Path) -> None:
    config = settings(tmp_path)
    first, second = payload(config), payload(config)
    store = Store(config.database)
    gateway = GatewayStore(tmp_path / "routes.sqlite")
    try:
        store.accept(first)
        store.accept(second)
        store.db.execute(
            "UPDATE commands SET next_attempt=9999999999 WHERE id=?", (str(first.command_id),)
        )
        store.db.commit()
        assert store.pending_command() is None
        store.finish(str(first.command_id))
        next_command = store.pending_command()
        assert next_command is not None and next_command["id"] == str(second.command_id)
        lock = command_frame(first.command_id, 1, 2**32 - 1)
        unlock = command_frame(second.command_id, 2, 2**32 - 1)
        gateway.accept(lock)
        gateway.accept(unlock)
        gateway.db.execute(
            "UPDATE routes SET next_attempt=9999999999 WHERE command_id=?", (str(first.command_id),)
        )
        gateway.db.commit()
        assert gateway.pending() == []
        gateway.finish(Frame(first.command_id, 0x180, b"\x00"))
        assert gateway.pending() == [unlock]
    finally:
        store.close()
        gateway.close()


@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_redirect_is_blocked_without_forwarding_device_token(
    tmp_path: Path, status: int
) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.accept(command)
    store.finish(str(command.command_id))
    calls = 0

    def redirect(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, headers={"Location": "https://other-host.example/reports"})

    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(redirect), follow_redirects=False
        ) as client:
            await report_once(store, config, client)
            assert not await report_once(store, config, client)
        assert calls == 1
        assert (
            store.db.execute("SELECT state,error FROM reports ORDER BY sequence").fetchone()[
                "state"
            ]
            == "blocked"
        )
    finally:
        store.close()


@pytest.mark.parametrize(
    "address",
    [
        "http://user:password@127.0.0.1:8000",
        "http://127.0.0.1:8000?token=secret",
        "http://127.0.0.1:8000#secret",
    ],
)
def test_api_base_url_cannot_hide_credentials(tmp_path: Path, address: str) -> None:
    raw = settings(tmp_path).model_dump() | {"api_url": address}
    with pytest.raises(ValidationError):
        DeviceSettings.model_validate(raw)


@pytest.mark.parametrize("failure", [ConnectionRefusedError, ConnectionResetError])
async def test_can_send_unavailable_peer_keeps_process_alive(
    monkeypatch: pytest.MonkeyPatch, failure: type[OSError]
) -> None:
    bus = VirtualCAN(udp_port(), udp_port())
    try:
        mocked = AsyncMock(side_effect=failure())
        monkeypatch.setattr(asyncio.get_running_loop(), "sock_sendto", mocked)
        await bus.send(command_frame(uuid4(), 1, 2**32 - 1))
        mocked.assert_awaited_once()
    finally:
        bus.close()


@pytest.mark.parametrize("legacy_ledger", [False, True])
def test_tbox_ledger_cannot_be_reassigned_to_another_vehicle(
    tmp_path: Path, legacy_ledger: bool
) -> None:
    config = settings(tmp_path)
    command = payload(config)
    store = Store(config.database)
    if not legacy_ledger:
        store.bind_identity(config.tenant_id, str(config.vehicle_id))
    store.accept(command)
    store.close()
    store = Store(config.database)
    try:
        with pytest.raises(ValueError, match="identity_mismatch"):
            store.bind_identity(config.tenant_id, str(uuid4()))
        store.bind_identity(config.tenant_id, str(config.vehicle_id))
        with pytest.raises(ValueError, match="identity_mismatch"):
            store.bind_identity("other-tenant", str(config.vehicle_id))
        assert store.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 1
        assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 1
    finally:
        store.close()


def test_backpressure_retains_unreported_results_and_allows_duplicate_recovery(
    tmp_path: Path,
) -> None:
    config = settings(tmp_path)
    first, second = payload(config), payload(config)
    store = Store(config.database, max_pending_commands=1)
    try:
        store.accept(first)
        store.finish(str(first.command_id))
        with pytest.raises(CapacityError):
            store.accept(second)
        assert not store.accept(first)
        assert store.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 1
        for _ in range(2):
            report = store.pending_report()
            assert report is not None
            store.report_result(report["sequence"], 200, 0)
        assert store.accept(second)
    finally:
        store.close()


def test_quarantine_capacity_does_not_discard_existing_evidence(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.sqlite", max_quarantine_records=1)
    try:
        store.quarantine(b"first", "invalid")
        store.quarantine(b"first", "invalid")
        with pytest.raises(CapacityError):
            store.quarantine(b"second", "invalid")
        assert store.db.execute("SELECT count(*) FROM quarantine").fetchone()[0] == 1
    finally:
        store.close()


def test_disk_reserve_prevents_new_command_without_ack_outbox(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database, min_free_bytes=2**63 - 1)
    try:
        with pytest.raises(CapacityError):
            store.accept(payload(config))
        assert store.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 0
        assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    finally:
        store.close()


def test_all_three_ledgers_have_bounded_inspection(tmp_path: Path) -> None:
    config = settings(tmp_path)
    tbox = Store(config.database)
    gateway = GatewayStore(tmp_path / "gateway.sqlite")
    body = BodyStore(tmp_path / "body.sqlite")
    try:
        for _ in range(3):
            command = payload(config)
            tbox.accept(command)
            frame = command_frame(command.command_id, 1, 2**32 - 1)
            gateway.accept(frame)
            body.execute(frame)
        first = tbox.reconcile(limit=1)
        second = tbox.reconcile(limit=1, offset=1)
        assert first["counts"] == {"commands": 3, "reports": 3, "quarantine": 0}
        assert len(first["commands"]) == 1  # type: ignore[arg-type]
        assert first["commands"] != second["commands"]
        assert len(gateway.reconcile(limit=1)["routes"]) == 1  # type: ignore[arg-type]
        assert len(body.reconcile(limit=1)["executions"]) == 1  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            tbox.reconcile(limit=1001)
        with pytest.raises(ValueError):
            gateway.reconcile(offset=-1)
        with pytest.raises(ValueError):
            body.reconcile(limit=0)
    finally:
        tbox.close()
        gateway.close()
        body.close()


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, None),
        ("120", 120.0),
        ("86400", 86400.0),
        ("garbage", None),
        ("-1", None),
        ("NaN", None),
        ("Wed, 01 Jan 2020 00:00:00 GMT", 0.0),
    ],
)
def test_retry_after_is_bounded_and_validated(value: str | None, expected: float | None) -> None:
    assert parse_retry_after(value) == expected


async def test_http_retry_after_is_persisted(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.accept(payload(config))
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(429, headers={"Retry-After": "120"})
            )
        ) as client:
            before = datetime.now(UTC).timestamp()
            await report_once(store, config, client)
        report = store.db.execute("SELECT * FROM reports").fetchone()
        assert report["state"] == "pending" and report["next_attempt"] >= before + 120
        assert store.pending_report() is None
    finally:
        store.close()


def test_jitter_remains_bounded() -> None:
    samples = {backoff(1, 30) for _ in range(10)}
    assert len(samples) > 1
    assert all(0.32 <= value <= 0.48 for value in samples)
    assert backoff(100000, 30) <= 30


def test_settings_never_print_password_on_validation_failure(tmp_path: Path) -> None:
    raw = settings(tmp_path).model_dump() | {"mqtt_password": "super-secret-password"}
    valid = DeviceSettings.model_validate(raw)
    assert "super-secret-password" not in repr(valid)
    with pytest.raises(ValidationError) as caught:
        DeviceSettings.model_validate(raw | {"can_port": -1})
    assert "super-secret-password" not in str(caught.value)


@pytest.mark.parametrize("token", ["x" * 8193, "nonascii-\u4e2d", "a\nb"])
async def test_invalid_token_file_does_not_crash_report_loop(tmp_path: Path, token: str) -> None:
    config = settings(tmp_path)
    config.token_file.write_text(token, encoding="utf-8")
    store = Store(config.database)
    store.accept(payload(config))
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: pytest.fail("invalid token must not reach HTTP transport")
            )
        ) as client:
            await report_once(store, config, client)
        assert store.db.execute("SELECT state FROM reports").fetchone()[0] == "pending"
    finally:
        store.close()


def test_precise_expiry_and_cached_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from simulators.vehicle_device.can import precise_command_frame

    frame = precise_command_frame(uuid4(), 1, datetime.fromtimestamp(100.750001, UTC))
    gateway = GatewayStore(tmp_path / "gateway.db")
    body = BodyStore(tmp_path / "body.db")
    try:
        assert len(frame.data) == 7
        assert gateway.accept(frame) == (True, None)
        monkeypatch.setattr("simulators.body_ecu.service.time.time", lambda: 100.75)
        assert body.execute(frame).data == b"\x00"
        monkeypatch.setattr("simulators.body_ecu.service.time.time", lambda: 101.0)
        assert body.execute(frame).data == b"\x00"
        expired = precise_command_frame(uuid4(), 2, datetime.fromtimestamp(100.75, UTC))
        assert body.execute(expired).data == b"\x02"
    finally:
        gateway.close()
        body.close()


def test_legacy_ledger_migration_preserves_frame_version(tmp_path: Path) -> None:
    config = settings(tmp_path)
    command = payload(config)
    with sqlite3.connect(config.database) as db:
        db.execute(
            "CREATE TABLE commands (id TEXT PRIMARY KEY, payload TEXT NOT NULL, "
            "state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
            "next_attempt REAL NOT NULL DEFAULT 0)"
        )
        db.execute(
            "INSERT INTO commands(id,payload,state) VALUES (?,?,'pending')",
            (str(command.command_id), command.model_dump_json()),
        )
    store = Store(config.database)
    try:
        row = store.pending_command()
        assert row is not None and row["can_version"] == 1
        newer = payload(config)
        store.accept(newer)
        assert (
            store.db.execute(
                "SELECT can_version FROM commands WHERE id=?", (str(newer.command_id),)
            ).fetchone()[0]
            == 2
        )
    finally:
        store.close()
    reopened = Store(config.database)
    try:
        row = reopened.pending_command()
        assert row is not None and row["can_version"] == 1
    finally:
        reopened.close()


def test_precise_frame_rejects_naive_deadline() -> None:
    from simulators.vehicle_device.can import precise_command_frame

    with pytest.raises(ValueError, match="naive_command_expiry"):
        precise_command_frame(uuid4(), 1, datetime(2026, 1, 1))


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["body", "gateway"])
async def test_ecu_bind_failure_closes_partial_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    from simulators.body_ecu import __main__ as body_main
    from simulators.gateway import service as gateway_service

    module = body_main if role == "body" else gateway_service
    store = (
        BodyStore(tmp_path / "body.db") if role == "body" else GatewayStore(tmp_path / "gateway.db")
    )
    monkeypatch.setattr(
        module, "BodyStore" if role == "body" else "GatewayStore", lambda path: store
    )
    front = AsyncMock()
    front.close = lambda: closed.append(True)
    closed: list[bool] = []
    calls = 0

    def bus(local: int, peer: int) -> AsyncMock:
        nonlocal calls
        calls += 1
        if role == "gateway" and calls == 1:
            return front
        raise OSError("address already in use")

    monkeypatch.setattr(module, "VirtualCAN", bus)
    with pytest.raises(OSError, match="address already"):
        if role == "body":
            await body_main.serve(tmp_path / "body.db", 19001, 19003, False)
        else:
            await gateway_service.serve(tmp_path / "gateway.db", 19002, 19000, 19003, 19001, False)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        store.db.execute("SELECT 1")
    assert closed == ([True] if role == "gateway" else [])


@pytest.mark.parametrize("value", ["86401", "9" * 5000, "Fri, 01 Jan 2100 00:00:00 GMT"])
def test_retry_after_over_policy_is_not_clamped(value: str) -> None:
    from simulators.vehicle_device.runtime import RetryAfterTooLong

    with pytest.raises(RetryAfterTooLong):
        parse_retry_after(value)


def test_jitter_survives_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("simulators.vehicle_device.store.random.uniform", lambda a, b: a)
    low = backoff(1000, 30)
    monkeypatch.setattr("simulators.vehicle_device.store.random.uniform", lambda a, b: b)
    high = backoff(1000, 30)
    assert 0 < low < high <= 30


def test_health_totals_cover_all_pages(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    try:
        for _ in range(3):
            store.accept(payload(config))
        view = store.reconcile(limit=1)
        commands = view["commands"]
        health = view["health"]
        assert isinstance(commands, list) and len(commands) == 1
        assert isinstance(health, dict)
        assert health["command_states"] == {"pending": 3}
        assert health["report_states"] == {"pending": 3}
        assert health["sqlite_bytes"] > 0
        assert health["oldest_unfinished_report_at"] is not None
    finally:
        store.close()


@pytest.mark.parametrize("status", [401, 403])
def test_auth_retry_exhaustion_survives_restart_and_blocks_result(
    tmp_path: Path, status: int
) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.bind_identity(config.tenant_id, str(config.vehicle_id))
    command = payload(config)
    store.accept(command)
    store.finish(str(command.command_id))
    ack = store.pending_report()
    assert ack is not None
    for attempt in range(8):
        store.report_result(ack["sequence"], status, attempt)
    store.close()
    recovered = Store(config.database)
    try:
        assert recovered.pending_report() is None
        row = recovered.db.execute(
            "SELECT state,error,attempts FROM reports WHERE sequence=?", (ack["sequence"],)
        ).fetchone()
        assert tuple(row) == ("blocked", "AUTH_RETRY_EXHAUSTED", 8)
        health = recovered.reconcile()["health"]
        assert isinstance(health, dict) and health["auth_blocked_reports"] == 1
    finally:
        recovered.close()


def test_ledger_limit_preserves_duplicate_ack_and_rejects_new_work(tmp_path: Path) -> None:
    config = settings(tmp_path)
    store = Store(config.database, max_ledger_records=1)
    command = payload(config)
    try:
        assert store.accept(command)
        assert not store.accept(command)
        with pytest.raises(CapacityError, match="ledger_capacity"):
            store.accept(payload(config))
        assert store.db.execute("SELECT count(*) FROM commands").fetchone()[0] == 1
    finally:
        store.close()
