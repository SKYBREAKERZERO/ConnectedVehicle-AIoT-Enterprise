import os
from pathlib import Path

from scripts.day17_release import write_json
from scripts.day18_evidence import evaluate, verify


def test_day18_full_evidence_gate() -> None:
    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    write_json(directory / "day18-acceptance.json", evaluate(directory))
    verify(directory)
