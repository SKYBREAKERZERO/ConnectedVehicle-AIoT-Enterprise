from __future__ import annotations

import json
from pathlib import Path

import httpx2 as httpx
import pytest

from simulators.vehicle_device.runtime import report_once
from simulators.vehicle_device.store import Store
from tests.unit.test_device_simulator import payload, settings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "receipt", [{"bad": True}, {"command_id": "wrong", "status": "acknowledged"}, None]
)
async def test_invalid_success_receipt_blocks_without_losing_event(
    tmp_path: Path, receipt: object
) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.accept(command)
    try:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=receipt))
        ) as client:
            assert await report_once(store, config, client)
            assert not await report_once(store, config, client)
        row = store.db.execute("SELECT state,payload FROM reports").fetchone()
        assert row["state"] == "blocked"
        assert json.loads(row["payload"])["event_id"]
    finally:
        store.close()


@pytest.mark.asyncio
async def test_timeout_retries_same_event_after_restart(tmp_path: Path) -> None:
    config = settings(tmp_path)
    command = payload(config)
    store = Store(config.database)
    store.accept(command)
    calls: list[bytes] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request.content)
        if len(calls) == 1:
            raise httpx.ReadTimeout("lost response", request=request)
        return httpx.Response(
            200, json={"command_id": str(command.command_id), "status": "acknowledged"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        try:
            await report_once(store, config, client)
        finally:
            store.close()
        restarted = Store(config.database)
        try:
            with restarted.db:
                restarted.db.execute("UPDATE reports SET next_attempt=0")
            await report_once(restarted, config, client)
            assert calls[0] == calls[1]
            assert restarted.db.execute("SELECT state FROM reports").fetchone()[0] == "delivered"
        finally:
            restarted.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308, 399])
async def test_redirects_stay_blocked_after_restart(tmp_path: Path, status: int) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    store.accept(payload(config))
    calls: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(status, headers={"Location": "https://example.com"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(respond), follow_redirects=False
    ) as client:
        try:
            assert await report_once(store, config, client)
        finally:
            store.close()
        restarted = Store(config.database)
        try:
            assert not await report_once(restarted, config, client)
            assert restarted.db.execute("SELECT state FROM reports").fetchone()[0] == "blocked"
            assert len(calls) == 1
        finally:
            restarted.close()


@pytest.mark.asyncio
async def test_missing_token_never_sends_report(tmp_path: Path) -> None:
    config = settings(tmp_path)
    config.token_file.unlink()
    store = Store(config.database)
    store.accept(payload(config))
    calls: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await report_once(store, config, client)
        assert not calls
        assert store.db.execute("SELECT state FROM reports").fetchone()[0] == "pending"
    finally:
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
@pytest.mark.parametrize("delay", [7200, 86400, 86401])
async def test_server_deadline_never_shortened(tmp_path: Path, status: int, delay: int) -> None:
    import time

    config = settings(tmp_path)
    store = Store(config.database)
    store.accept(payload(config))
    try:
        before = time.time()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(status, headers={"Retry-After": str(delay)})
            )
        ) as client:
            await report_once(store, config, client)
        row = store.db.execute("SELECT * FROM reports").fetchone()
        if delay > 86400:
            assert row["state"] == "blocked"
            assert row["error"] == "HTTP_RETRY_AFTER_TOO_LONG"
        else:
            assert row["state"] == "pending"
            assert row["next_attempt"] >= before + delay
        assert store.pending_report() is None
    finally:
        store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("reply_status", ["acknowledged", "failed"])
async def test_terminal_report_requires_matching_receipt(tmp_path: Path, reply_status: str) -> None:
    config = settings(tmp_path)
    store = Store(config.database)
    command = payload(config)
    store.accept(command)
    store.finish(str(command.command_id))
    try:
        with store.db:
            store.db.execute("UPDATE reports SET state='delivered' WHERE sequence=1")
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"command_id": str(command.command_id), "status": reply_status}
                )
            )
        ) as client:
            await report_once(store, config, client)
        row = store.db.execute("SELECT state,error FROM reports WHERE sequence=2").fetchone()
        assert tuple(row) == ("blocked", "HTTP_INVALID_RECEIPT")
    finally:
        store.close()
