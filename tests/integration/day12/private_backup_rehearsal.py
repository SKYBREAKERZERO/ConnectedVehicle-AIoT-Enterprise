"""Local-only rehearsal of an existing private Day11 dump; never upload its contents."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from enterprise_platform.database.engine import create_database_engine
from tests.e2e.test_independent_runtimes import docker
from tests.integration.day12.migration_support import HEAD, LEGACY, snapshot, start_harness


def validate_paths(backup: Path, expected_sha256: str, output: Path) -> None:
    if output.resolve() == backup.resolve():
        raise ValueError("Report destination must differ from the source backup")
    if os.path.lexists(output):
        raise FileExistsError("Report destination already exists; select a new path")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("Expected SHA256 must be 64 lowercase hexadecimal characters")
    with backup.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected_sha256:
        raise ValueError("Day11 backup digest mismatch")


def publish_report(output: Path, report: dict[str, object]) -> None:
    """Publish a complete report without overwriting any concurrently created destination."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output.parent, prefix=".day11-report-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(report, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


async def run(backup: Path, expected_sha256: str, output: Path) -> None:
    validate_paths(backup, expected_sha256, output)
    with tempfile.TemporaryDirectory(prefix="day11-private-rehearsal-") as temporary:
        directory = Path(temporary).resolve()
        if not directory.is_relative_to(Path(tempfile.gettempdir()).resolve()):
            raise ValueError("Invalid temporary rehearsal workspace")
        harness = start_harness(directory)
        try:
            harness.backup = backup.resolve()
            harness.backup_sha256 = expected_sha256
            # Deliberate owner/ACL cutover in an isolated clone, never the source database.
            settings = harness.restore("private_day11_clone", preserve_acl=False)
            harness.grants(settings, release=True)
            engine = create_database_engine(settings)
            try:
                before = await snapshot(engine)
                if before["revision"] != LEGACY:
                    raise ValueError("Backup is not the expected Day11 revision")
                harness.upgrade(settings)
                after = await snapshot(engine)
                if after["revision"] != HEAD or after["data"] != before["data"]:
                    raise ValueError("Private backup migration changed historical data")
                harness.upgrade(settings)
                if await snapshot(engine) != after:
                    raise ValueError("Private backup repeat migration changed state")
                report = {
                    "scope": "private-local-backup",
                    "verified_at_utc": datetime.now(UTC).isoformat(),
                    "backup_sha256": expected_sha256,
                    "revision_before": before["revision"],
                    "revision_after": after["revision"],
                    "historical_data": before["data"],
                    "owner_acl_reprovisioned": True,
                    "migration_identity": "migration_owner",
                    "superuser_migration": False,
                    "data_preserved": True,
                    "repeat_unchanged": True,
                }
                publish_report(output, report)
                print("Private Day11 backup: restored, upgraded and repeated without data changes")
            finally:
                await engine.dispose()
        finally:
            docker("rm", "-f", harness.container)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("backup", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument(
        "--output", type=Path, default=Path(".runtime-reports/private-day11-upgrade.json")
    )
    args = parser.parse_args()
    asyncio.run(run(args.backup, args.sha256, args.output))


if __name__ == "__main__":
    main()
