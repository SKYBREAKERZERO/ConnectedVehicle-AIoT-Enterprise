"""Build immutable candidate and historical application images for local staging."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from scripts.day36_staging import ROOT, command

INPUTS = (
    "pyproject.toml",
    "README.md",
    "apps",
    "connected_vehicle",
    "enterprise_platform",
    "simulators",
)


def application_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for entry in INPUTS:
        path = root / entry
        for item in sorted(path.rglob("*") if path.is_dir() else [path]):
            if item.is_file() and "__pycache__" not in item.parts and item.suffix != ".pyc":
                digest.update(item.relative_to(root).as_posix().encode() + b"\0")
                digest.update(item.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def build(baseline: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise ValueError("Full historical commit SHA required")
    candidate = command(["git", "rev-parse", "HEAD"])
    command(["git", "merge-base", "--is-ancestor", baseline, candidate])
    # Reject modified build inputs; unrelated local user edits are preserved.
    dirty = command(["git", "status", "--porcelain", "--", *INPUTS, "Dockerfile", ".dockerignore"])
    if dirty:
        raise ValueError("Commit build inputs before recording candidate identity")
    result: dict[str, Any] = {"candidate_sha": candidate, "baseline_sha": baseline}
    with tempfile.TemporaryDirectory(prefix="cv-day36-build-") as temporary:
        context = Path(temporary)
        archive = subprocess.run(
            ["git", "archive", baseline, *INPUTS], cwd=ROOT, capture_output=True, check=True
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(context, filter="data")
        for name in ("Dockerfile", ".dockerignore"):
            shutil.copyfile(ROOT / name, context / name)
        for role, revision, source in (
            ("baseline", baseline, context),
            ("candidate", candidate, ROOT),
        ):
            tag = "cv-day36-" + role + ":" + revision
            command(
                ["docker", "build", "--build-arg", "REVISION=" + revision, "-t", tag, str(source)],
                timeout=900,
            )
            image = json.loads(command(["docker", "image", "inspect", tag]))[0]
            if image["Config"]["Labels"]["org.opencontainers.image.revision"] != revision:
                raise ValueError("Image revision label mismatch")
            result[role] = {
                "image_digest": image["Id"],
                "revision": revision,
                "application_sha256": application_hash(source),
                "dependency_freeze_sha256": hashlib.sha256(
                    command(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "--network=none",
                            "--read-only",
                            "--cap-drop=ALL",
                            image["Id"],
                            "python",
                            "-m",
                            "pip",
                            "freeze",
                        ]
                    ).encode()
                ).hexdigest(),
            }
    if result["baseline"]["image_digest"] == result["candidate"]["image_digest"]:
        raise ValueError("A distinct historical and candidate image is required")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.baseline)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
