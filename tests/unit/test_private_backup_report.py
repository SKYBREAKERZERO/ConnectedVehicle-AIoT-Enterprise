from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sys
from multiprocessing.queues import Queue
from multiprocessing.synchronize import Barrier
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.integration.day12.private_backup_rehearsal import (
    main,
    publish_report,
    run,
    validate_paths,
)


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


def test_default_cli_runs_keep_distinct_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    backup = tmp_path / "backup.dump"
    original = b"read-only source"
    backup.write_bytes(original)
    digest = hashlib.sha256(original).hexdigest()
    directory = tmp_path / ".runtime-reports"
    directory.mkdir()
    previous = directory / "private-day11-upgrade.json"
    previous.write_bytes(b"previous acceptance report")
    outputs: list[Path] = []

    async def completed_rehearsal(source: Path, expected: str, output: Path) -> None:
        validate_paths(source, expected, output)
        publish_report(output, {"attempt": len(outputs)})
        outputs.append(output)

    monkeypatch.setattr(sys, "argv", ["private-rehearsal", str(backup), "--sha256", digest])
    # Even a frozen clock cannot cause the default filenames to collide.
    with (
        patch("tests.integration.day12.private_backup_rehearsal.run", completed_rehearsal),
        patch("tests.integration.day12.private_backup_rehearsal.datetime") as clock,
    ):
        clock.now.return_value.strftime.return_value = "20261012T000000000000Z"
        main()
        first = outputs[0].read_bytes()
        main()
    assert len(outputs) == 2 and outputs[0] != outputs[1]
    assert outputs[0].read_bytes() == first
    assert json.loads(outputs[1].read_text()) == {"attempt": 1}
    assert previous.read_bytes() == b"previous acceptance report"
    assert backup.read_bytes() == original
    assert capsys.readouterr().out.count("Report saved:") == 2


@pytest.mark.parametrize("target", ["backup", "existing-report"])
def test_cli_rejects_unsafe_output_before_database_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    backup = tmp_path / "backup.dump"
    original = b"original database dump"
    backup.write_bytes(original)
    output = backup if target == "backup" else tmp_path / "report.json"
    if target == "existing-report":
        output.write_bytes(b"previous report")
    previous = output.read_bytes()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "private-rehearsal",
            str(backup),
            "--sha256",
            hashlib.sha256(original).hexdigest(),
            "--output",
            str(output),
        ],
    )
    with patch("tests.integration.day12.private_backup_rehearsal.start_harness") as start:
        with pytest.raises(SystemExit) as failed:
            main()
        assert failed.value.code == 2
        start.assert_not_called()
    assert output.read_bytes() == previous and backup.read_bytes() == original
    error = capsys.readouterr().err
    assert error.startswith("error:") and "Traceback" not in error


def competing_publisher(
    backup: Path,
    digest: str,
    output: Path,
    writer: str,
    ready: Barrier,
    outcomes: Queue[tuple[str, str]],
) -> None:
    validate_paths(backup, digest, output)
    # Both processes must finish preflight before either attempts publication.
    ready.wait(timeout=20)
    try:
        publish_report(output, {"writer": writer, "payload": writer * 10000})
    except FileExistsError:
        outcomes.put(("collision", writer))
    else:
        outcomes.put(("published", writer))


def test_two_processes_cannot_overwrite_each_others_reports(tmp_path: Path) -> None:
    backup = tmp_path / "backup.dump"
    original = b"source backup remains immutable"
    backup.write_bytes(original)
    output = tmp_path / "shared-report.json"
    context = multiprocessing.get_context("spawn")
    ready = context.Barrier(2)
    outcomes = context.Queue()
    processes = [
        context.Process(
            target=competing_publisher,
            args=(backup, hashlib.sha256(original).hexdigest(), output, writer, ready, outcomes),
        )
        for writer in ("writer-a", "writer-b")
    ]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=25)
            assert not process.is_alive() and process.exitcode == 0
        results = [outcomes.get(timeout=5) for _ in processes]
        assert sorted(status for status, _ in results) == ["collision", "published"]
        winner = next(writer for status, writer in results if status == "published")
        assert json.loads(output.read_text()) == {"writer": winner, "payload": winner * 10000}
        assert backup.read_bytes() == original
        assert not list(tmp_path.glob(".day11-report-*"))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        outcomes.close()
        outcomes.join_thread()
