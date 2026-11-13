"""Strict Linux amd64 / Python 3.12 wheel-hash locks; no dynamic CI resolution."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
LOCKS = ROOT / "infra/staging/requirements"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def packages(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})", line)
        if not match or normalized(match[1]) in result:
            raise ValueError("Every unique dependency must have an exact version and wheel SHA256")
        result[normalized(match[1])] = match[2]
    if not result:
        raise ValueError("Empty dependency lock")
    return result


def validate(project: Path = ROOT / "pyproject.toml") -> dict[str, Any]:
    metadata = tomllib.loads(project.read_text(encoding="utf-8"))
    expected = {
        "python": "3.12",
        "platform": "linux/amd64",
        "runtime": metadata["project"]["dependencies"],
        "build": metadata["build-system"]["requires"] + ["pip"],
        "ci": metadata["project"]["dependencies"]
        + metadata["project"]["optional-dependencies"]["dev"]
        + metadata["build-system"]["requires"]
        + ["pip"],
    }
    if json.loads((LOCKS / "inputs.json").read_text(encoding="utf-8")) != expected:
        raise ValueError("Dependency inputs changed: regenerate and review complete hash locks")
    for kind in ("runtime", "build", "ci"):
        locked = packages(LOCKS / (kind + ".lock"))
        for value in expected[kind]:
            requirement = Requirement(value)
            version = locked.get(normalized(requirement.name))
            if version is None or version not in requirement.specifier:
                raise ValueError("Lock does not satisfy a direct requirement")
    return {
        "platform": "linux/amd64",
        "python": "3.12",
        "files": {
            p.name: sha(p)
            for p in (
                LOCKS / "runtime.lock",
                LOCKS / "build.lock",
                LOCKS / "ci.lock",
                LOCKS / "inputs.json",
            )
        },
    }
