"""Per-probe evidence is source/run/attempt-bound and cannot be replayed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scripts import day38_enterprise as enterprise
from scripts import day38_probe_evidence as proof


def provenance(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("GITHUB_REPOSITORY", enterprise.REPO)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    return proof.identity("a" * 40, 123, 2)


def test_all_12_receipts_and_hash_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = provenance(monkeypatch)
    monkeypatch.chdir(Path(__file__).resolve().parents[2])
    folder = tmp_path / "proofs"
    for scenario in proof.CASES:
        proof.run_case(scenario, folder / f"probe-{scenario}.json")
    proof.make_index(folder, folder / "probe-index.json")
    members = proof.members_from_dir(folder, include_index=True)
    assert proof.check_members(members, source["candidate_sha"], 123, 2)["count"] == 12
    with pytest.raises(ValueError, match="index"):
        proof.check_members(members, source["candidate_sha"], 123, 3)
    with pytest.raises(ValueError, match="incomplete"):
        proof.check_members(
            {k: v for k, v in members.items() if "zip-symlink" not in k},
            "a" * 40,
            123,
            2,
        )
    bad = {**members, "probe-zip-symlink.json": b"{}"}
    with pytest.raises(ValueError, match="tamper"):
        proof.check_members(bad, "a" * 40, 123, 2)
    with pytest.raises(ValueError, match="inventory|overwrite"):
        proof.make_index(folder, folder / "probe-index.json")


def test_malformed_identity_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    provenance(monkeypatch)
    with pytest.raises(ValueError, match="run ID"):
        proof.identity("a" * 40, 0, 1)
    with pytest.raises(ValueError, match="attempt"):
        proof.identity("a" * 40, 2, 0)
    with pytest.raises(ValueError, match="SHA"):
        proof.identity("notasha", 2, 1)
