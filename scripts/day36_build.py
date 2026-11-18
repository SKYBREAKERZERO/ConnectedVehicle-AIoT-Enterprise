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

from scripts.day36_lock import LOCKS, normalized, packages, sha, validate
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


def build(baseline: str, archives: Path) -> dict[str, Any]:
    archives = output_archives(archives)
    if not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise ValueError("Full historical commit SHA required")
    candidate = command(["git", "rev-parse", "HEAD"])
    command(["git", "merge-base", "--is-ancestor", baseline, candidate])
    # Reject modified build inputs; unrelated local user edits are preserved.
    dirty = command(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            *INPUTS,
            "Dockerfile",
            ".dockerignore",
            "infra/staging/requirements",
        ]
    )
    if dirty:
        raise ValueError("Commit build inputs before recording candidate identity")
    result: dict[str, Any] = {
        "candidate_sha": candidate,
        "baseline_sha": baseline,
        "dependency_locks": validate(),
    }
    with tempfile.TemporaryDirectory(prefix="cv-day36-build-") as temporary:
        context = Path(temporary)
        archive = subprocess.run(
            ["git", "archive", baseline, *INPUTS], cwd=ROOT, capture_output=True, check=True
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(context, filter="data")
        for name in ("Dockerfile", ".dockerignore"):
            shutil.copyfile(ROOT / name, context / name)
        shutil.copytree(LOCKS, context / "infra/staging/requirements")
        validate(context / "pyproject.toml")
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
                "installed_packages": inventory(image["Id"]),
            }
            archive_path = archives / (role + ".tar")
            command(["docker", "save", "--output", str(archive_path), tag], timeout=300)
            result[role]["archive_sha256"] = sha(archive_path)
            result[role]["archive_name"] = archive_path.name
    if result["baseline"]["image_digest"] == result["candidate"]["image_digest"]:
        raise ValueError("A distinct historical and candidate image is required")
    return result


def output_archives(directory: Path) -> Path:
    # Explicit task directory, never a shared Docker resource or existing archive.
    directory.mkdir(parents=True, exist_ok=True)
    if any((directory / (role + ".tar")).exists() for role in ("baseline", "candidate")):
        raise ValueError("Use a new image archive directory")
    return directory


def inventory(image: str) -> dict[str, str]:
    code = (
        "import importlib.metadata as m,json; "
        "print(json.dumps({d.metadata['Name']:d.version for d in m.distributions()}))"
    )
    found = json.loads(
        command(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                image,
                "python",
                "-c",
                code,
            ]
        )
    )
    installed = {normalized(k): v for k, v in found.items()}
    project = installed.pop("connected-vehicle-aiot-enterprise", None)
    if project != "0.1.0" or installed != packages(LOCKS / "runtime.lock"):
        raise ValueError("Actual image dependency closure differs from the hash lock")
    return installed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.baseline, args.archives.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
