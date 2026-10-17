from __future__ import annotations

import os
from pathlib import Path

from scripts.day17_release import evaluate, verify_readiness, write_json


def test_combined_operations_and_ota_release_gate() -> None:
    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    result = evaluate(directory)
    assert result["decision"] == "ready_for_local_release"
    assert result["checks"]["ota_foundation"] is True
    write_json(directory / "day17-readiness.json", result)
    verify_readiness(directory)
