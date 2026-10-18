"""Require all real prerequisite evidence from this same integration run."""

import os
from pathlib import Path

from scripts.day17_release import write_json
from scripts.day19_evidence import evaluate, verify


def test_campaign_acceptance_requires_complete_fresh_evidence() -> None:
    directory = Path(os.environ["RUNTIME_EVIDENCE_DIR"])
    expected = evaluate(directory)
    write_json(directory / "day19-acceptance.json", expected)
    assert verify(directory) == expected
