from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from simulators.vehicle_device.ownership import RuntimeAlreadyRunningError, runtime_lock
from simulators.vehicle_device.store import Store, print_reconciliation


def test_same_ledger_has_one_owner(tmp_path: Path) -> None:
    path = tmp_path / "device.sqlite"
    with (
        runtime_lock(path),
        pytest.raises(RuntimeAlreadyRunningError),
        runtime_lock(path.parent / "." / path.name),
    ):
        pytest.fail("Second owner accepted")
    with runtime_lock(path, wait_seconds=1):
        pass


def test_distinct_ledgers_can_run_together(tmp_path: Path) -> None:
    with runtime_lock(tmp_path / "a.sqlite"), runtime_lock(tmp_path / "b.sqlite"):
        pass


def test_forced_process_exit_releases_ownership(tmp_path: Path) -> None:
    path = tmp_path / "device.sqlite"
    ready = tmp_path / "ready"
    script = tmp_path / "child.py"
    script.write_text(
        "import sys, time\n"
        "from pathlib import Path\n"
        "from simulators.vehicle_device.ownership import runtime_lock\n"
        "with runtime_lock(Path(sys.argv[1])):\n"
        "    Path(sys.argv[2]).write_text('ready')\n"
        "    time.sleep(60)\n",
        encoding="utf-8",
    )
    with subprocess.Popen([sys.executable, str(script), str(path), str(ready)]) as process:
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert ready.exists(), "Child did not acquire runtime ownership"
            with pytest.raises(RuntimeAlreadyRunningError), runtime_lock(path):
                pass
        finally:
            process.kill()
            process.wait(timeout=5)
    with runtime_lock(path, wait_seconds=1):
        pass


def test_read_inspection_allowed_but_replay_requires_offline_runtime(tmp_path: Path) -> None:
    path = tmp_path / "device.sqlite"
    store = Store(path)
    store.close()
    with runtime_lock(path):
        print_reconciliation(path, False)
        with pytest.raises(RuntimeAlreadyRunningError):
            print_reconciliation(path, True)


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["tbox", "body", "gateway"])
async def test_runtime_rejects_second_owner_before_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    from unittest.mock import AsyncMock

    from simulators.body_ecu import __main__ as body
    from simulators.gateway import service as gateway
    from simulators.vehicle_device import runtime as tbox
    from tests.unit.test_device_simulator import settings

    config = settings(tmp_path)
    module = {"tbox": tbox, "body": body, "gateway": gateway}[role]
    start = AsyncMock()
    monkeypatch.setattr(module, "_serve", start)
    with runtime_lock(config.database), pytest.raises(RuntimeAlreadyRunningError):
        if role == "tbox":
            await tbox.serve(config)
        elif role == "body":
            await body.serve(config.database, 19001, 19003, False)
        else:
            await gateway.serve(config.database, 19002, 19000, 19003, 19001, False)
    start.assert_not_awaited()
