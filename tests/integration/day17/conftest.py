from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest

from tests.integration.day12.conftest import local_environment as local_environment


@pytest.fixture(scope="module", autouse=True)
def day17_run() -> None:
    if "DAY16_EVIDENCE_RUN_ID" not in os.environ:
        identifier = "day17-" + uuid4().hex
        os.environ["DAY16_EVIDENCE_RUN_ID"] = identifier
        os.environ["RUNTIME_EVIDENCE_DIR"] = str(Path(".runtime-reports") / identifier)
