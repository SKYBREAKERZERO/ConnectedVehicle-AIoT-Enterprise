"""Synthetic supply-policy mutations; these are NOT real image-scan evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from scripts import day36_supply as supply
from scripts.day36_lock import LOCKS, packages, sha, validate


@pytest.fixture
def supply_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    candidate = "a" * 40
    monkeypatch.setattr(
        supply,
        "context",
        lambda: {"candidate_sha": candidate, "run_id": "local", "run_attempt": "local"},
    )
    images: dict[str, Any] = {
        "candidate_sha": candidate,
        "baseline_sha": "b" * 40,
        "dependency_locks": validate(),
    }
    binding: dict[str, Any] = {
        "context": supply.context(),
        "scanner": supply.TRIVY,
        "dependency_locks": validate(),
        "generated_at": datetime.now(UTC).isoformat(),
        "database": {"Version": 2, "UpdatedAt": datetime.now(UTC).isoformat()},
        "images": {},
    }
    for i, role in enumerate(supply.ROLES):
        revision = candidate if role == "candidate" else "b" * 40
        image: dict[str, Any] = {
            "image_digest": "sha256:" + str(i + 1) * 64,
            "revision": revision,
            "archive_sha256": "f" * 64,
            "archive_name": role + ".tar",
            "installed_packages": packages(LOCKS / "runtime.lock"),
        }
        config = "sha256:" + str(i + 3) * 64
        libs = [
            {"Name": n, "Version": v, "Identifier": {"PURL": "pkg:pypi/" + n + "@" + v}}
            for n, v in image["installed_packages"].items()
        ]
        scan = {
            "CreatedAt": datetime.now(UTC).isoformat(),
            "SchemaVersion": 2,
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": config,
                "ImageConfig": {
                    "config": {"Labels": {"org.opencontainers.image.revision": revision}}
                },
            },
            "Results": [
                {"Class": "os-pkgs", "Packages": []},
                {"Class": "lang-pkgs", "Packages": libs},
            ],
        }
        (tmp_path / (role + "-trivy.json")).write_text(json.dumps(scan))
        record = {
            "image_digest": image["image_digest"],
            "revision": revision,
            "archive_sha256": image["archive_sha256"],
            "config_digest": config,
            "scan_exit_code": 0,
            "scan_sha256": sha(tmp_path / (role + "-trivy.json")),
        }
        bom = {
            "bomFormat": "CycloneDX",
            "metadata": {
                "properties": [
                    {"name": k, "value": v} for k, v in supply.sbom_binding(image, record).items()
                ]
            },
            "components": [{"purl": p["Identifier"]["PURL"]} for p in libs],
        }
        (tmp_path / (role + "-sbom.json")).write_text(json.dumps(bom))
        record["proofs"] = {
            name: sha(tmp_path / name) for name in (role + "-trivy.json", role + "-sbom.json")
        }
        binding["images"][role], images[role] = record, image
    (tmp_path / "images.json").write_text(json.dumps(images))
    (tmp_path / "supply-chain.json").write_text(json.dumps(binding))
    return tmp_path


@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "high",
        "critical",
        "unknown",
        "invalid-severity",
        "scanner-failure",
        "missing-role",
        "wrong-attempt",
        "stale-db",
        "wrong-image",
        "missing-sbom",
        "wrong-sbom-commit",
        "empty-sbom",
        "missing-library",
        "changed-lock",
        "missing-proof",
    ],
)
def test_supply_admission_is_fail_closed(supply_proof: Path, mutation: str) -> None:
    folder = supply_proof
    binding = json.loads((folder / "supply-chain.json").read_text())
    record = binding["images"]["candidate"]
    scan = json.loads((folder / "candidate-trivy.json").read_text())
    bom = json.loads((folder / "candidate-sbom.json").read_text())
    if mutation in {"high", "critical", "unknown", "invalid-severity"}:
        severity = "MALFORMED" if mutation == "invalid-severity" else mutation.upper()
        scan["Results"][0]["Vulnerabilities"] = [
            {"Severity": severity, "VulnerabilityID": "CVE-test", "PkgName": "test"}
        ]
    elif mutation == "scanner-failure":
        record["scan_exit_code"] = 2
    elif mutation == "missing-role":
        binding["images"].pop("baseline")
    elif mutation == "wrong-attempt":
        binding["context"]["run_attempt"] = "999"
    elif mutation == "stale-db":
        binding["database"]["UpdatedAt"] = "2020-01-01T00:00:00Z"
    elif mutation == "wrong-image":
        scan["Metadata"]["ImageID"] = "sha256:" + "f" * 64
    elif mutation == "wrong-sbom-commit":
        next(p for p in bom["metadata"]["properties"] if p["name"] == "cv:commit")["value"] = (
            "c" * 40
        )
    elif mutation == "empty-sbom":
        bom["components"] = []
    elif mutation == "missing-library":
        scan["Results"][1]["Packages"].pop()
    elif mutation == "changed-lock":
        binding["dependency_locks"]["files"]["runtime.lock"] = "f" * 64
    (folder / "candidate-trivy.json").write_text(json.dumps(scan))
    # Update envelope hashes to test semantic admission, not only byte tamper checks.
    record["scan_sha256"] = sha(folder / "candidate-trivy.json")
    next(p for p in bom["metadata"]["properties"] if p["name"] == "cv:scan_sha256")["value"] = (
        record["scan_sha256"]
    )
    (folder / "candidate-sbom.json").write_text(json.dumps(bom))
    record["proofs"] = {
        name: sha(folder / name) for name in ("candidate-trivy.json", "candidate-sbom.json")
    }
    if mutation == "missing-proof":
        record["proofs"].pop("candidate-trivy.json")
    if mutation == "missing-sbom":
        (folder / "candidate-sbom.json").unlink()
    (folder / "supply-chain.json").write_text(json.dumps(binding))
    if mutation == "none":
        assert supply.verify(folder)["decision"] == "SUPPLY_CHAIN_VERIFIED"
    else:
        with pytest.raises((ValueError, OSError)):
            supply.verify(folder)
