from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from prometheus_client import generate_latest

from enterprise_platform.database.recovery import CommitOutcomeUnknown, recover_transaction
from enterprise_platform.observability.context import bind_observability_context
from enterprise_platform.observability.recovery import (
    RecoveryMonitor,
    monitoring_session,
    observe_recovery,
    recovery_scope,
)
from scripts.day16_demo import cleanup_owned, main
from tests.unit.test_transaction_recovery import database_error


async def test_retry_result_correlates_context_without_metric_cardinality(
    caplog: pytest.LogCaptureFixture,
) -> None:
    monitor = RecoveryMonitor()
    calls = 0

    async def operation() -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise database_error("55P03")
        return 7

    async def lookup() -> int | None:
        return None

    with (
        monitoring_session(monitor),
        bind_observability_context(request_id="req", correlation_id="corr", trace_id="c" * 32),
        recovery_scope("database", operation_id="a" * 32, fault_id="b" * 32),
    ):
        assert await recover_transaction(operation, lookup, base_delay=0.001) == 7
    rows = monitor.snapshot()
    assert [row["state"] for row in rows] == [
        "RUNNING",
        "FAULT_DETECTED",
        "CLASSIFIED",
        "RETRY",
        "VERIFY",
        "RECOVERED",
    ]
    assert all(
        row["operation_id"] == "a" * 32
        and row["fault_id"] == "b" * 32
        and row["request_id"] == "req"
        and row["correlation_id"] == "corr"
        and row["trace_id"] == "c" * 32
        for row in rows
    )
    metrics = generate_latest(monitor.registry).decode()
    assert 'state="RECOVERED"' in metrics
    assert (
        "operation_id=" not in metrics and "fault_id=" not in metrics and "trace_id=" not in metrics
    )
    log = next(
        row.getMessage().removeprefix("recovery_event ")
        for row in caplog.records
        if row.getMessage().startswith("recovery_event ")
    )
    assert json.loads(log)["operation_id"] == "a" * 32


async def test_monitor_failure_never_replays_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monitor = RecoveryMonitor()

    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("monitor down")

    monkeypatch.setattr(monitor, "record", unavailable)
    calls = 0

    async def operation() -> int:
        nonlocal calls
        calls += 1
        return 1

    async def lookup() -> int | None:
        raise AssertionError("must not reconcile")

    with monitoring_session(monitor):
        assert await recover_transaction(operation, lookup) == 1
    assert calls == 1


async def test_mismatched_reconciliation_cannot_emit_recovered() -> None:
    monitor = RecoveryMonitor()

    async def operation() -> int:
        raise CommitOutcomeUnknown()

    async def lookup() -> int | None:
        return 1

    def reject(result: int) -> None:
        raise ValueError("conflicting operation parameters")

    with monitoring_session(monitor), pytest.raises(ValueError):
        await recover_transaction(operation, lookup, validate=reject)
    assert monitor.snapshot()[-1]["state"] == "ESCALATED"
    assert "RECOVERED" not in [row["state"] for row in monitor.snapshot()]


async def test_concurrent_scopes_do_not_leak_identifiers() -> None:
    monitor = RecoveryMonitor()

    async def run(value: str) -> None:
        with recovery_scope("worker", operation_id=value * 32, fault_id=value * 32):
            await asyncio.sleep(0)
            observe_recovery("FAULT_DETECTED", 1)

    with monitoring_session(monitor):
        await asyncio.gather(run("a"), run("b"))
    assert {row["operation_id"] for row in monitor.snapshot()} == {"a" * 32, "b" * 32}


def test_demo_refuses_existing_output_before_starting_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.argv", ["demo", "--output", str(tmp_path)])
    launch = Mock()
    monkeypatch.setattr("scripts.day16_demo.subprocess.run", launch)
    with pytest.raises(FileExistsError):
        main()
    launch.assert_not_called()


def test_demo_cleanup_is_scoped_to_exact_run_label(monkeypatch: pytest.MonkeyPatch) -> None:
    execute = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 0, stdout="a" * 12 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0),
        ]
    )
    monkeypatch.setattr("scripts.day16_demo.subprocess.run", execute)
    cleanup_owned("b" * 32)
    assert execute.call_args_list[0].args[0][-1] == "label=cv.day16.run=" + "b" * 32
    assert execute.call_args_list[1].args[0] == ["docker", "rm", "-f", "a" * 12]
