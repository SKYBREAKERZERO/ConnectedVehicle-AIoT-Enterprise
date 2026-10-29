"""Actual local process faults over SQLite. Not a cloud identity/State fault test."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.day29_evidence import source_digest
from scripts.iac.deploy_governance import ROOT, run_identity
from tests.unit.iac.test_release_revalidation import setup_revalidation


@pytest.fixture(scope="module", autouse=True)
def stamp(record_testsuite_property: Callable[[str, object], None]) -> None:
    for k, v in {
        "day29_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day29_run_id": run_identity(),
        "day29_source_sha256": source_digest(),
    }.items():
        record_testsuite_property(k, v)


CHILD = """
import base64,json,os,sys,time
from pathlib import Path
from tests.unit.iac.test_recovery_approval import open_approvals
from tests.unit.iac.test_trusted_state_registry import TARGET,FakeClock,registry
from scripts.iac.release_revalidation import ReleaseRevalidator
p=Path(sys.argv[1]);v=json.loads(Path(sys.argv[2]).read_text());a=v['args']
a['raw']=base64.b64decode(a['raw']);a['plan']=base64.b64decode(a['plan'])
r=ReleaseRevalidator(p,registry=registry(p,TARGET),approvals=open_approvals(p),
    evidence_authority=lambda _:True,observation_authority=lambda _:True,clock=FakeClock())
mode=v['mode'];release=v['release_id']
if mode=='after-claim':
    r.releases.request=lambda *a,**k:os._exit(74)
if mode=='after-verified':
    original=r.releases.advance
    def stop(*a,**k):original(*a,**k);os._exit(75)
    r.releases.advance=stop
if 'ready' in v:
    Path(v['ready']).write_text('ready');deadline=time.monotonic()+15
    while not Path(v['start']).exists():
        if time.monotonic()>deadline:sys.exit(99)
        time.sleep(.01)
try:r.verify(release,**a)
except ValueError:sys.exit(23)
sys.exit(0)
"""


def bundle(path: Path, args: dict[str, Any], mode: str, release_id: str, **extra: str) -> None:
    args = {
        **args,
        "raw": base64.b64encode(args["raw"]).decode(),
        "plan": base64.b64encode(args["plan"]).decode(),
    }
    args["evidence"] = {**args["evidence"], "request_id": release_id}
    path.write_text(
        json.dumps({"args": args, "mode": mode, "release_id": release_id, **extra}),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("mode", "code", "release_state"),
    [("after-claim", 74, None), ("after-verified", 75, "VERIFIED")],
)
def test_process_exit_keeps_ambiguous_claim_spent_without_resuming(
    tmp_path: Path, mode: str, code: int, release_state: str | None
) -> None:
    db = tmp_path / "governance.sqlite"
    v, args, _ = setup_revalidation(db)
    payload = tmp_path / "private.json"
    bundle(payload, args, mode, "new-release")
    child = subprocess.run(
        [sys.executable, "-c", CHILD, str(db), str(payload)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert child.returncode == code, child.stderr
    with sqlite3.connect(db) as connection:
        assert (
            connection.execute("SELECT status FROM day29_revalidations").fetchone()[0] == "CLAIMED"
        )
        row = connection.execute("SELECT state FROM releases WHERE id='new-release'").fetchone()
        assert (None if row is None else row[0]) == release_state
    with pytest.raises(ValueError):
        v.verify("new-release", **args)
    args["evidence"]["request_id"] = "retry-release"
    with pytest.raises(ValueError):
        v.verify("retry-release", **args)
    assert v.releases.state("previous-release") == "INTERRUPTED"


def test_two_processes_revalidate_one_receipt_with_exactly_one_verified_result(
    tmp_path: Path,
) -> None:
    db = tmp_path / "governance.sqlite"
    v, args, _ = setup_revalidation(db)
    start = tmp_path / "start"
    children = []
    try:
        for i in range(2):
            payload = tmp_path / f"private-{i}.json"
            bundle(
                payload,
                args,
                "normal",
                f"new-{i}",
                start=str(start),
                ready=str(tmp_path / f"ready-{i}"),
            )
            children.append(
                subprocess.Popen(
                    [sys.executable, "-c", CHILD, str(db), str(payload)],
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        deadline = time.monotonic() + 15
        while not all((tmp_path / f"ready-{i}").exists() for i in range(2)):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        start.write_text("go")
        errors = [p.communicate(timeout=25)[1] for p in children]
        assert sorted(p.returncode for p in children) == [0, 23], errors
        with sqlite3.connect(db) as connection:
            assert (
                connection.execute(
                    "SELECT count(*) FROM day29_revalidations WHERE status='VERIFIED'"
                ).fetchone()[0]
                == 1
            )
            assert (
                connection.execute(
                    "SELECT count(*) FROM releases WHERE state='VERIFIED'"
                ).fetchone()[0]
                == 1
            )
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
