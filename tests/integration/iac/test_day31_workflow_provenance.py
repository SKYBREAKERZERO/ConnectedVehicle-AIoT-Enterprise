"""A real Git graph exercises PR merge identity independently of policy mocks."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scripts.iac.ci_baseline_policy import REPOSITORY, select_baseline


def test_real_git_merge_graph_binds_baseline_to_event(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(tmp_path), *args], text=True, stderr=subprocess.PIPE
        ).strip()

    git("init")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "fixture")
    (tmp_path / "base").write_text("base")
    git("add", "base")
    git("commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    git("checkout", "-b", "feature")
    (tmp_path / "feature").write_text("feature")
    git("add", "feature")
    git("commit", "-m", "feature")
    head = git("rev-parse", "HEAD")
    git("checkout", "-b", "candidate", base)
    git("merge", "--no-ff", "feature", "-m", "candidate")
    candidate = git("rev-parse", "HEAD")
    event = {
        "repository": {"full_name": REPOSITORY, "default_branch": "main"},
        "number": 15,
        "pull_request": {
            "base": {"sha": base, "ref": "main", "repo": {"full_name": REPOSITORY}},
            "head": {"sha": head},
            "merge_commit_sha": candidate,
            "state": "open",
        },
    }
    result = select_baseline(
        event_name="pull_request",
        event=event,
        candidate=candidate,
        ref="refs/pull/15/merge",
        parents=git("show", "-s", "--format=%P", candidate).split(),
        ancestor=lambda a, b: (
            subprocess.run(
                ["git", "-C", str(tmp_path), "merge-base", "--is-ancestor", a, b],
                capture_output=True,
            ).returncode
            == 0
        ),
        default_tip=base,
    )
    assert result["baseline_sha"] == base and candidate != head
