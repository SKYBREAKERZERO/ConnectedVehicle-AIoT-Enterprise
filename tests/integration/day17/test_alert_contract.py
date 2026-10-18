from __future__ import annotations

import pytest

from scripts.day17_rules import ROOT
from tests.e2e.test_independent_runtimes import docker


@pytest.mark.integration
def test_budget_burn_fires_and_resolves_with_promtool() -> None:
    output = docker(
        "run",
        "--rm",
        "--entrypoint",
        "/bin/promtool",
        "-v",
        f"{ROOT}:/work:ro",
        "-w",
        "/work",
        "prom/prometheus:v3.5.0",
        "test",
        "rules",
        "tests/fixtures/day17/alerts.test.yml",
    )
    assert "SUCCESS" in output
