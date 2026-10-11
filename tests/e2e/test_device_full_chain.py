from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.e2e.test_independent_runtimes import exercise


@pytest.mark.e2e
@pytest.mark.integration
def test_cloud_to_body_ecu_with_crash_recovery(tmp_path: Path) -> None:
    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(exercise(tmp_path, device_chain=True))
