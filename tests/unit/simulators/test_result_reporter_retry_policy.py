"""Retry-After + jitter regression tests over the durable device SQLite outbox."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from uuid import uuid4

import pytest

from simulators.vehicle_device.execution_store import (
    DeliveryState,
    DeviceCommand,
    DeviceExecutionStore,
)
from simulators.vehicle_device.result_reporter import DeviceResultReporter

VEHICLE_ID = "00000000-0000-4000-8000-000000000001"
CLOCK = datetime(2026, 10, 11, 1, 15, tzinfo=UTC)


@dataclass(frozen=True)
class FakeResponse:
    status_code: int
    headers: Mapping[str, str] = field(default_factory=dict)
    payload: dict[str, object] | None = None

    def json(self) -> object:
        return self.payload


class FakeHTTP:
    def __init__(self, *responses: FakeResponse | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str], dict[str, object]]] = []

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Mapping[str, object],
    ) -> FakeResponse:
        self.calls.append((url, dict(headers), dict(json)))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def build(tmp_path: Path) -> tuple[DeviceExecutionStore, DeviceCommand]:
    store = DeviceExecutionStore(tmp_path / "tbox.db", tenant_id="tenant-1", vehicle_id=VEHICLE_ID)
    command = DeviceCommand(
        command_id=str(uuid4()),
        tenant_id="tenant-1",
        vehicle_id=VEHICLE_ID,
        command_type="lock",
        created_at=CLOCK - timedelta(seconds=1),
        expires_at=CLOCK + timedelta(seconds=59),
    )
    store.receive(
        command,
        trusted_tenant_id="tenant-1",
        trusted_vehicle_id=VEHICLE_ID,
        now=CLOCK,
    )
    return store, command


def next_attempt(store: DeviceExecutionStore, event_id: str) -> datetime:
    with sqlite3.connect(store.path) as db:
        record = db.execute(
            "SELECT next_attempt_at FROM device_report_outbox WHERE event_id=?",
            (event_id,),
        ).fetchone()
    assert record is not None
    return datetime.fromisoformat(record[0])


@pytest.mark.parametrize(
    ("unit", "attempt", "expected"),
    [
        (0.0, 1, 1),
        (0.999, 1, 1),
        (0.0, 2, 1),
        (0.999, 2, 2),
        (0.0, 3, 2),
        (0.999, 3, 4),
        (0.0, 8, 30),
        (0.999, 8, 60),
        (0.0, 100, 30),
    ],
)
def test_bounded_equal_jitter(tmp_path: Path, unit: float, attempt: int, expected: int) -> None:
    store, _ = build(tmp_path)
    reporter = DeviceResultReporter(
        store=store, client=FakeHTTP(), token_supplier=lambda: "token", random_unit=lambda: unit
    )
    assert reporter._delay(attempt) == expected


@pytest.mark.parametrize("unit", [-0.1, 1.0, float("nan"), float("inf")])
def test_invalid_random_source_fails_closed(tmp_path: Path, unit: float) -> None:
    store, _ = build(tmp_path)
    reporter = DeviceResultReporter(
        store=store, client=FakeHTTP(), token_supplier=lambda: "token", random_unit=lambda: unit
    )
    with pytest.raises(ValueError, match="random_unit"):
        reporter._delay(1)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 429, 500, 503, 599])
async def test_retry_after_seconds_is_persisted_and_prevents_premature_retry(
    tmp_path: Path, status: int
) -> None:
    store, command = build(tmp_path)
    client = FakeHTTP(
        FakeResponse(status, {"rEtRy-AfTeR": "120"}),
        FakeResponse(200, payload={"command_id": command.command_id, "status": "acknowledged"}),
    )
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=120)
    assert not store.begin_execution(command.command_id, now=CLOCK)
    assert (await reporter.flush_once(now=CLOCK + timedelta(seconds=119))).claimed == 0
    assert len(client.calls) == 1

    restarted = DeviceExecutionStore(store.path, tenant_id="tenant-1", vehicle_id=VEHICLE_ID)
    again = DeviceResultReporter(
        store=restarted, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await again.flush_once(now=CLOCK + timedelta(seconds=120))).delivered == 1
    assert client.calls[0][2] == client.calls[1][2]
    assert store.report_state(event_id) is DeliveryState.DELIVERED


@pytest.mark.asyncio
async def test_retry_after_http_date_rounds_up_and_honors_server_deadline(
    tmp_path: Path,
) -> None:
    store, _ = build(tmp_path)
    server_date = format_datetime(CLOCK + timedelta(seconds=90), usegmt=True)
    client = FakeHTTP(FakeResponse(503, {"Retry-After": server_date}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=90)
    assert (await reporter.flush_once(now=CLOCK + timedelta(seconds=89))).claimed == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["nope", "-12", "3.5", "", "0x10"])
async def test_invalid_retry_after_uses_jitter_fallback(tmp_path: Path, header: str) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP(FakeResponse(429, {"Retry-After": header}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_past_http_date_uses_jitter_fallback(tmp_path: Path) -> None:
    store, _ = build(tmp_path)
    yesterday = format_datetime(CLOCK - timedelta(days=1), usegmt=True)
    client = FakeHTTP(FakeResponse(503, {"Retry-After": yesterday}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_one_day_retry_after_is_allowed_by_sqlite(tmp_path: Path) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP(FakeResponse(429, {"Retry-After": "86400"}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(days=1)
    assert (await reporter.flush_once(now=CLOCK + timedelta(hours=23))).claimed == 0


@pytest.mark.asyncio
async def test_retry_after_beyond_policy_blocks_without_early_retry(tmp_path: Path) -> None:
    store, command = build(tmp_path)
    client = FakeHTTP(FakeResponse(503, {"Retry-After": "86401"}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).blocked == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert store.report_state(event_id) is DeliveryState.BLOCKED
    assert (await reporter.flush_once(now=CLOCK + timedelta(days=2))).claimed == 0
    assert not store.begin_execution(command.command_id, now=CLOCK)
    with sqlite3.connect(store.path) as db:
        row = db.execute(
            "SELECT last_error_code FROM device_report_outbox WHERE event_id=?", (event_id,)
        ).fetchone()
    assert row == ("HTTP_RETRY_AFTER_TOO_LONG",)


@pytest.mark.asyncio
async def test_redirect_remains_blocked_even_if_retry_after_present(tmp_path: Path) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP(FakeResponse(307, {"Retry-After": "1"}))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).blocked == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert store.report_state(event_id) is DeliveryState.BLOCKED
    assert (await reporter.flush_once(now=CLOCK + timedelta(days=1))).claimed == 0


@pytest.mark.asyncio
async def test_retry_without_header_exponential_growth_across_restart(
    tmp_path: Path,
) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP(FakeResponse(500), FakeResponse(503), FakeResponse(429))
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.999
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=1)
    restarted = DeviceExecutionStore(store.path, tenant_id="tenant-1", vehicle_id=VEHICLE_ID)
    reporter2 = DeviceResultReporter(
        store=restarted, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.999
    )
    assert (await reporter2.flush_once(now=CLOCK + timedelta(seconds=1))).deferred == 1
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=3)
    assert (await reporter2.flush_once(now=CLOCK + timedelta(seconds=3))).deferred == 1
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=7)
    assert all(call[2] == client.calls[0][2] for call in client.calls)


@pytest.mark.asyncio
async def test_retry_after_shorter_than_local_jitter_does_not_accelerate_retry(
    tmp_path: Path,
) -> None:
    store, _ = build(tmp_path)
    # Second attempt backoff grows to 2 seconds; Retry-After: 1 is only a minimum.
    client = FakeHTTP(
        FakeResponse(503),
        FakeResponse(429, {"Retry-After": "1"}),
    )
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "token", random_unit=lambda: 0.999
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    assert (await reporter.flush_once(now=CLOCK + timedelta(seconds=1))).deferred == 1
    event_id = str(client.calls[0][2]["event_id"])
    assert next_attempt(store, event_id) == CLOCK + timedelta(seconds=3)


@pytest.mark.asyncio
async def test_missing_token_jitters_without_contacting_network(tmp_path: Path) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP()
    reporter = DeviceResultReporter(
        store=store, client=client, token_supplier=lambda: "", random_unit=lambda: 0.0
    )
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    assert client.calls == []
    with sqlite3.connect(store.path) as db:
        row = db.execute(
            "SELECT next_attempt_at, last_error_code FROM device_report_outbox"
        ).fetchone()
    assert row == (
        (CLOCK + timedelta(seconds=30)).isoformat(timespec="microseconds"),
        "TOKEN_UNAVAILABLE",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["", "abc\ndef", "abc\rdef", "é", "x" * 8193])
async def test_invalid_token_never_reaches_transport(tmp_path: Path, token: str) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP()
    reporter = DeviceResultReporter(store=store, client=client, token_supplier=lambda: token)
    summary = await reporter.flush_once(now=CLOCK)
    assert summary.deferred == 1
    assert not client.calls


@pytest.mark.asyncio
async def test_token_supplier_failure_defers_event(tmp_path: Path) -> None:
    store, _ = build(tmp_path)
    client = FakeHTTP()

    def unavailable() -> str:
        raise OSError("token file absent")

    reporter = DeviceResultReporter(store=store, client=client, token_supplier=unavailable)
    assert (await reporter.flush_once(now=CLOCK)).deferred == 1
    assert not client.calls


def test_result_report_waits_for_ack_delivery(tmp_path: Path) -> None:
    store, command = build(tmp_path)
    with store._connect() as connection:
        store._insert_report(
            connection, command_id=command.command_id, status="succeeded", now=CLOCK
        )
        connection.commit()
    ack = store.lease_reports(now=CLOCK, limit=10)
    assert len(ack) == 1 and ack[0].status == "acknowledged"
    store.block(ack[0], error_code="HTTP_409")
    assert not store.lease_reports(now=CLOCK)
    store.requeue_blocked(ack[0].event_id, now=CLOCK)
    retry = store.lease_reports(now=CLOCK)
    assert len(retry) == 1 and retry[0].event_id == ack[0].event_id
    assert store.mark_delivered(retry[0])
    results = store.lease_reports(now=CLOCK)
    assert len(results) == 1 and results[0].status == "succeeded"
