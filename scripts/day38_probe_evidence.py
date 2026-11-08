"""Bounded Day38 negative-probe receipts and independent source-bound validation.

This module records denials only; evidence NEVER authorizes a release or AWS use.
The original raw case receipts are retained, not merely a success counter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts import day38_enterprise as enterprise
from scripts import day38_readiness as verifier

CASES = enterprise.PROBE_CASES
SCHEMA = "day38.probe.v1"
INDEX_SCHEMA = "day38.probe-index.v1"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError("Day38 probe BLOCKED: " + message)


def identity(sha: str, run_id: int, attempt: int) -> dict[str, Any]:
    require(verifier.SHA.fullmatch(sha) is not None, "invalid candidate SHA")
    require(type(run_id) is int and run_id > 0, "invalid run ID")
    require(type(attempt) is int and attempt > 0, "invalid attempt")
    return {
        "repository": enterprise.REPO,
        "candidate_sha": sha,
        "run_id": run_id,
        "run_attempt": attempt,
    }


def write_once(path: Path, document: dict[str, Any]) -> None:
    require(not path.exists() and not path.is_symlink(), "refuse to overwrite receipt")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def run_case(name: str, output: Path) -> None:
    require(name in CASES, "unknown probe")
    enterprise.probe(name)  # Must reject malformed input, otherwise raises.
    origin = enterprise.current_identity()
    verifier_source = Path("scripts/day38_readiness.py")
    require(
        verifier_source.is_file() and not verifier_source.is_symlink(),
        "actual verifier source missing",
    )
    write_once(
        output,
        {
            "schema_version": SCHEMA,
            "scenario": name,
            "decision": "DENIED_AS_EXPECTED",
            "source": identity(
                origin["candidate_sha"], origin["run_id"], origin["run_attempt"]
            ),
            "verifier_sha256": sha256(verifier_source.read_bytes()),
            "release_authorized": False,
        },
    )


def check_members(
    members: dict[str, bytes], candidate: str, run_id: int, attempt: int
) -> dict[str, Any]:
    """Independently validate a sealed archive's exact 12 raw receipts + index."""
    expected = {f"probe-{name}.json" for name in CASES} | {"probe-index.json"}
    require(set(members) == expected, "incomplete/extra independent probe receipts")
    source = identity(candidate, run_id, attempt)
    index = verifier.strict_json(members["probe-index.json"])
    hashes = index.get("cases")
    source_hash = index.get("verifier_sha256")
    require(
        set(index)
        == {
            "schema_version",
            "source",
            "cases",
            "count",
            "verifier_sha256",
            "release_authorized",
        }
        and index.get("schema_version") == INDEX_SCHEMA
        and index.get("source") == source
        and index.get("release_authorized") is False
        and type(index.get("count")) is int
        and index["count"] == len(CASES)
        and isinstance(hashes, dict)
        and set(hashes) == set(CASES)
        and isinstance(source_hash, str)
        and verifier.HASH.fullmatch(source_hash) is not None,
        "probe index or source mismatch",
    )
    if not isinstance(hashes, dict):
        raise ValueError("invalid probe case hash inventory")
    for name in CASES:
        raw = members[f"probe-{name}.json"]
        record = verifier.strict_json(raw)
        require(
            set(record)
            == {
                "schema_version",
                "scenario",
                "source",
                "decision",
                "verifier_sha256",
                "release_authorized",
            }
            and record["schema_version"] == SCHEMA
            and record["scenario"] == name
            and record["source"] == source
            and record["decision"] == "DENIED_AS_EXPECTED"
            and record["verifier_sha256"] == source_hash
            and record["release_authorized"] is False
            and hashes[name] == sha256(raw),
            "probe tamper, skip, replay, or wrong verdict: " + name,
        )
    return index


def members_from_dir(folder: Path, *, include_index: bool) -> dict[str, bytes]:
    require(folder.is_dir() and not folder.is_symlink(), "unsafe probe directory")
    expected = {f"probe-{name}.json" for name in CASES}
    if include_index:
        expected.add("probe-index.json")
    paths = list(folder.iterdir())
    require({p.name for p in paths} == expected and len(paths) == len(expected), "probe inventory")
    require(all(p.is_file() and not p.is_symlink() for p in paths), "linked probe receipt")
    require(all(p.stat().st_size <= 10_000 for p in paths), "oversized probe receipt")
    return {p.name: p.read_bytes() for p in paths}


def make_index(folder: Path, output: Path) -> None:
    records = members_from_dir(folder, include_index=False)
    origin = enterprise.current_identity()
    source = identity(origin["candidate_sha"], origin["run_id"], origin["run_attempt"])
    first = verifier.strict_json(records[f"probe-{CASES[0]}.json"])
    index = {
        "schema_version": INDEX_SCHEMA,
        "source": source,
        "cases": {case: sha256(records[f"probe-{case}.json"]) for case in CASES},
        "count": len(CASES),
        "verifier_sha256": first.get("verifier_sha256"),
        "release_authorized": False,
    }
    raw = (json.dumps(index, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    check_members(
        {**records, "probe-index.json": raw},
        source["candidate_sha"],
        source["run_id"],
        source["run_attempt"],
    )
    write_once(output, index)


def verify_directory(folder: Path) -> dict[str, Any]:
    origin = enterprise.current_identity()
    return check_members(
        members_from_dir(folder, include_index=True),
        origin["candidate_sha"],
        origin["run_id"],
        origin["run_attempt"],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    case = sub.add_parser("run")
    case.add_argument("--scenario", required=True)
    case.add_argument("--output", required=True, type=Path)
    for mode in ("index", "verify"):
        cmd = sub.add_parser(mode)
        cmd.add_argument("--folder", required=True, type=Path)
        if mode == "index":
            cmd.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "run":
        run_case(args.scenario, args.output)
        print("DENIED_AS_EXPECTED", args.scenario)
    elif args.mode == "index":
        make_index(args.folder, args.output)
    else:
        print(json.dumps(verify_directory(args.folder), sort_keys=True))


if __name__ == "__main__":
    main()
