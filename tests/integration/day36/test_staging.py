"""Real local containers and stable-ingress rollback; missing Docker/images fails."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts.day36_staging import ROOT


@pytest.fixture(scope="module")
def deployment() -> tuple[dict[str, Any], Path]:
    folder = Path(os.environ["DAY36_REPORT_DIR"])
    images = json.loads((folder / "images.json").read_text())
    output = folder / "staging.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.day36_staging",
            "--baseline-image",
            images["baseline"]["image_digest"],
            "--candidate-image",
            images["candidate"]["image_digest"],
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        timeout=600,
    )
    return json.loads(output.read_text()), output


@pytest.fixture(autouse=True)
def binding(
    deployment: tuple[dict[str, Any], Path], record_property: Callable[[str, str], None]
) -> None:
    result, path = deployment
    for key in ("candidate_sha", "run_id", "run_attempt"):
        record_property(key, result[key])
    record_property("staging_sha256", hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize("fault", ["startup_exit", "readiness_503", "candidate_sigkill"])
def test_staging_fault(deployment: tuple[dict[str, Any], Path], fault: str) -> None:
    result, _ = deployment
    observation = [f for f in result["faults"] if f["name"] == fault]
    assert observation == [{"name": fault, "rejected": True, "rollback_verified": True}]


def test_staging_data_and_identity(deployment: tuple[dict[str, Any], Path]) -> None:
    result, _ = deployment
    assert result["before"] == result["after"]
    assert result["before"]["remote_commands"]["count"] == 1
    assert result["before"]["outbox_events"]["count"] == 1
    assert result["stable_ingress_verified"] is True
    assert result["schema_rollback_executed"] is False


def test_staging_image_permissions(deployment: tuple[dict[str, Any], Path]) -> None:
    result, _ = deployment
    assert result["runtime_security_verified"] is True
    assert result["baseline_image_digest"] != result["image_digest"]
    assert result["production_authorized"] is False
