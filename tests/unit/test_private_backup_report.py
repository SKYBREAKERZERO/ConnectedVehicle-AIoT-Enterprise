from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from tests.integration.day12.private_backup_rehearsal import publish_report, run, validate_paths


@pytest.mark.parametrize("alias", ["same", "relative", "hardlink"])
async def test_report_cannot_overwrite_source_backup(tmp_path: Path, alias: str) -> None:
    backup = tmp_path / "backup.dump"
    original = b"private backup must remain unchanged"
    backup.write_bytes(original)
    output = backup if alias == "same" else tmp_path / "." / "backup.dump"
    if alias == "hardlink":
        output = tmp_path / "alias.json"
        os.link(backup, output)
    with pytest.raises((ValueError, FileExistsError)):
        await run(backup, hashlib.sha256(original).hexdigest(), output)
    assert backup.read_bytes() == original


def test_report_publish_race_preserves_existing_file(tmp_path: Path) -> None:
    backup = tmp_path / "backup.dump"
    backup.write_bytes(b"backup")
    output = tmp_path / "report.json"
    validate_paths(backup, hashlib.sha256(b"backup").hexdigest(), output)
    output.write_bytes(b"created by another invocation")
    with pytest.raises(FileExistsError):
        publish_report(output, {"result": "passed"})
    assert output.read_bytes() == b"created by another invocation"
    assert not list(tmp_path.glob(".day11-report-*"))


async def test_bad_digest_rejected_before_starting_database(tmp_path: Path) -> None:
    backup = tmp_path / "backup.dump"
    backup.write_bytes(b"backup")
    with pytest.raises(ValueError, match="digest mismatch"):
        await run(backup, "0" * 64, tmp_path / "report.json")
    assert not (tmp_path / "report.json").exists()


def test_incomplete_report_is_never_published(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    with pytest.raises(TypeError):
        publish_report(output, {"invalid": object()})
    assert not output.exists()
    assert not list(tmp_path.glob(".day11-report-*"))
