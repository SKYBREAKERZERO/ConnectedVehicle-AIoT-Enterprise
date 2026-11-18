"""Fail-closed dual-image CVE/SBOM admission. No registry or production authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.day35_workflow_gate import load
from scripts.day36_build import inventory
from scripts.day36_lock import LOCKS, normalized, packages, sha, validate
from scripts.day36_staging import command

TRIVY = (
    "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
)
ROLES = ("baseline", "candidate")
BLOCK = {"HIGH", "CRITICAL", "UNKNOWN"}


def context() -> dict[str, str]:
    return {
        "candidate_sha": command(["git", "rev-parse", "HEAD"]),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    }


def recent(value: str, hours: int) -> None:
    age = (datetime.now(UTC) - datetime.fromisoformat(value.replace("Z", "+00:00"))).total_seconds()
    if not 0 <= age <= hours * 3600:
        raise ValueError("Stale/future scanner or vulnerability database evidence")


def archive_config(path: Path, image: dict[str, Any]) -> str:
    if path.is_symlink() or sha(path) != image["archive_sha256"]:
        raise ValueError("Image archive SHA256 mismatch")
    with tarfile.open(path) as archive:

        def read(name: str) -> bytes:
            member = archive.getmember(name)
            if not member.isfile() or member.size > 3_000_000:
                raise ValueError("Unsafe image metadata member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Missing image config")
            return stream.read()

        manifests = json.loads(read("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("Exactly one image required per archive")
        raw = read(manifests[0]["Config"])
        config = json.loads(raw)
        config_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if (
            config["config"]["Labels"]["org.opencontainers.image.revision"] != image["revision"]
            or config["config"]["User"] != "10001:10001"
            or config["architecture"] != "amd64"
            or config["os"] != "linux"
        ):
            raise ValueError("Archive revision, architecture or runtime user mismatch")
        # Docker classic IDs are config IDs; containerd may use an OCI manifest/index ID.
        if image["image_digest"] != config_digest:
            blob = read("blobs/sha256/" + image["image_digest"].removeprefix("sha256:"))
            if "sha256:" + hashlib.sha256(blob).hexdigest() != image["image_digest"]:
                raise ValueError("Engine image identity not authenticated by archive")
            descriptor = json.loads(blob)
            if "manifests" in descriptor:
                choices = [
                    d
                    for d in descriptor["manifests"]
                    if d.get("platform") == {"architecture": "amd64", "os": "linux"}
                ]
                if len(choices) != 1:
                    raise ValueError("Ambiguous archive platform")
                manifest = read("blobs/sha256/" + choices[0]["digest"].removeprefix("sha256:"))
                if "sha256:" + hashlib.sha256(manifest).hexdigest() != choices[0]["digest"]:
                    raise ValueError("OCI manifest digest mismatch")
                descriptor = json.loads(manifest)
            if descriptor["config"]["digest"] != config_digest:
                raise ValueError("OCI image does not reference the scanned config")
        return config_digest


def scan_findings(scan: dict[str, Any], config: str, revision: str) -> list[dict[str, str]]:
    recent(scan["CreatedAt"], 2)
    if (
        scan.get("SchemaVersion") != 2
        or scan.get("ArtifactType") != "container_image"
        or scan["Metadata"]["ImageID"] != config
        or scan["Metadata"]["ImageConfig"]["config"]["Labels"]["org.opencontainers.image.revision"]
        != revision
    ):
        raise ValueError("Trivy image/config/source identity mismatch")
    results = scan["Results"]
    if not {"os-pkgs", "lang-pkgs"} <= {r["Class"] for r in results}:
        raise ValueError("Trivy must inventory OS and application libraries")
    if not any(r.get("Packages") for r in results if r["Class"] == "lang-pkgs"):
        raise ValueError("Empty Trivy library inventory")
    if any(
        v.get("Severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
        for r in results
        for v in r.get("Vulnerabilities", [])
    ):
        raise ValueError("Invalid vulnerability severity encoding")
    return [
        {"id": v["VulnerabilityID"], "package": v["PkgName"], "severity": v["Severity"]}
        for r in results
        for v in r.get("Vulnerabilities", [])
        if v["Severity"] in BLOCK
    ]


def verify(folder: Path, archives: Path | None = None, *, inspect: bool = False) -> dict[str, Any]:
    binding, images = load(folder / "supply-chain.json"), load(folder / "images.json")
    if binding["context"] != context() or binding["dependency_locks"] != validate():
        raise ValueError("Supply-chain source/Run/Attempt/lock mismatch")
    if (
        images["candidate_sha"] != context()["candidate_sha"]
        or images["dependency_locks"] != validate()
    ):
        raise ValueError("Image build source/lock mismatch")
    if binding["scanner"] != TRIVY or set(binding["images"]) != set(ROLES):
        raise ValueError("Scanner or dual-image supply evidence missing")
    recent(binding["generated_at"], 2)
    recent(binding["database"]["UpdatedAt"], 48)
    if type(binding["database"].get("Version")) is not int or binding["database"]["Version"] != 2:
        raise ValueError("Unsupported vulnerability DB schema")
    if (
        images["candidate"]["revision"] != context()["candidate_sha"]
        or images["baseline"]["revision"] != images["baseline_sha"]
        or images["candidate"]["image_digest"] == images["baseline"]["image_digest"]
    ):
        raise ValueError("Distinct baseline/candidate source and image identities required")
    facts: dict[str, Any] = {}
    for role in ROLES:
        image, record = images[role], binding["images"][role]
        if (
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image["image_digest"])
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", record["config_digest"])
            or not re.fullmatch(r"[0-9a-f]{40}", image["revision"])
        ):
            raise ValueError("Immutable full source and image identities required")
        if image["installed_packages"] != packages(LOCKS / "runtime.lock"):
            raise ValueError("Incomplete hash-locked runtime dependency inventory")
        if image["archive_name"] != role + ".tar":
            raise ValueError("Fixed role-scoped archive name required")
        for field in ("image_digest", "revision", "archive_sha256"):
            if record[field] != image[field]:
                raise ValueError("Supply/build binding mismatch")
        if (
            archives is not None
            and archive_config(archives / image["archive_name"], image) != record["config_digest"]
        ):
            raise ValueError("Trivy config does not match actual image TAR")
        for name, expected in record["proofs"].items():
            if name != Path(name).name or sha(folder / name) != expected:
                raise ValueError("Missing or changed scan/SBOM report")
        if set(record["proofs"]) != {role + "-trivy.json", role + "-sbom.json"}:
            raise ValueError("Exact scan and SBOM proofs required for each image")
        scan = load(folder / (role + "-trivy.json"))
        library_inventory = {
            (normalized(p["Name"]), p["Version"])
            for r in scan["Results"]
            if r["Class"] == "lang-pkgs"
            for p in r["Packages"]
        }
        if not set(image["installed_packages"].items()) <= library_inventory:
            raise ValueError("Trivy failed to inventory a locked runtime package")
        if record["scan_sha256"] != sha(folder / (role + "-trivy.json")):
            raise ValueError("SBOM scan hash is not the actual Trivy report")
        findings = scan_findings(scan, record["config_digest"], image["revision"])
        if type(record["scan_exit_code"]) is not int or record["scan_exit_code"] not in {0, 1}:
            raise ValueError("Failed Trivy execution: " + role)
        sbom = load(folder / (role + "-sbom.json"))
        properties = sbom["metadata"]["properties"]
        props = {p["name"]: p["value"] for p in properties}
        if len(props) != len(properties) or any(
            props.get(k) != v for k, v in sbom_binding(image, record).items()
        ):
            raise ValueError("SBOM image/source/scan/run binding mismatch")
        if sbom["bomFormat"] != "CycloneDX" or not sbom["components"]:
            raise ValueError("Empty or invalid CycloneDX SBOM")
        # Require all scanner package identities in the native SBOM; no empty-summary acceptance.
        scanned = {
            p["Identifier"]["PURL"]
            for r in scan["Results"]
            for p in r["Packages"]
            if p.get("Identifier", {}).get("PURL")
        }
        components = {p["purl"] for p in sbom["components"] if "purl" in p}
        if not scanned or not scanned <= components:
            raise ValueError("SBOM does not cover the actual scanner inventory")
        if inspect:
            info = json.loads(command(["docker", "image", "inspect", image["image_digest"]]))[0]
            if (
                info["Id"] != image["image_digest"]
                or info["Config"]["Labels"]["org.opencontainers.image.revision"]
                != image["revision"]
                or inventory(image["image_digest"]) != image["installed_packages"]
            ):
                raise ValueError("Loaded image or actual dependency inventory differs")
        facts[role] = {
            "image_digest": image["image_digest"],
            "revision": image["revision"],
            "scan_sha256": sha(folder / (role + "-trivy.json")),
            "sbom_sha256": sha(folder / (role + "-sbom.json")),
            "blocking_vulnerabilities": len(findings),
        }
    if any(v["blocking_vulnerabilities"] for v in facts.values()) or any(
        binding["images"][role]["scan_exit_code"] != 0 for role in ROLES
    ):
        raise ValueError(
            "Blocking image vulnerabilities or scanner failure: "
            + ", ".join(f"{r}={facts[r]['blocking_vulnerabilities']}" for r in ROLES)
        )
    return {
        "decision": "SUPPLY_CHAIN_VERIFIED",
        "images": facts,
        "dependency_locks": validate(),
        "production_authorized": False,
    }


def sbom_binding(image: dict[str, Any], record: dict[str, Any]) -> dict[str, str]:
    return {
        "cv:image_id": image["image_digest"],
        "cv:config_digest": record["config_digest"],
        "cv:commit": image["revision"],
        "cv:scan_sha256": record["scan_sha256"],
        "cv:run_id": context()["run_id"],
        "cv:run_attempt": context()["run_attempt"],
        "cv:runtime_lock_sha256": validate()["files"]["runtime.lock"],
    }


def scan(folder: Path, archives: Path, cache: Path) -> None:
    folder, archives, cache = folder.resolve(), archives.resolve(), cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    base = [
        "docker",
        "run",
        "--rm",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--mount",
        f"type=bind,source={folder},target=/reports",
        "--mount",
        f"type=bind,source={archives},target=/images,readonly",
        "--mount",
        f"type=bind,source={cache},target=/root/.cache/trivy",
        TRIVY,
    ]
    images = load(folder / "images.json")
    binding: dict[str, Any] = {
        "context": context(),
        "dependency_locks": validate(),
        "scanner": TRIVY,
        "images": {},
        "generated_at": datetime.now(UTC).isoformat(),
    }
    for role in ROLES:
        image = images[role]
        config = archive_config(archives / image["archive_name"], image)
        args = [
            *base,
            "image",
            "--input",
            "/images/" + image["archive_name"],
            "--scanners",
            "vuln",
            "--list-all-pkgs",
            "--ignorefile",
            "",
            "--ignore-unfixed=false",
            "--severity",
            "HIGH,CRITICAL,UNKNOWN",
            "--exit-code",
            "1",
            "--format",
            "json",
            "--output",
            "/reports/" + role + "-trivy.json",
            "--timeout",
            "10m",
            "--quiet",
        ]
        result = subprocess.run(args, capture_output=True, text=True, timeout=660)
        (folder / (role + "-scanner.log")).write_text(result.stderr, encoding="utf-8")
        native = folder / (role + "-trivy.json")
        if not native.is_file():
            raise ValueError("Trivy did not generate a vulnerability report: " + role)
        command(
            [
                *base,
                "convert",
                "--format",
                "cyclonedx",
                "--output",
                "/reports/" + role + "-sbom.json",
                "/reports/" + role + "-trivy.json",
            ],
            timeout=120,
        )
        record = {
            "image_digest": image["image_digest"],
            "revision": image["revision"],
            "archive_sha256": image["archive_sha256"],
            "config_digest": config,
            "scan_exit_code": result.returncode,
            "scan_sha256": sha(native),
        }
        bom = load(folder / (role + "-sbom.json"))
        bom["metadata"].setdefault("properties", []).extend(
            {"name": k, "value": v} for k, v in sbom_binding(image, record).items()
        )
        (folder / (role + "-sbom.json")).write_text(
            json.dumps(bom, indent=2) + "\n", encoding="utf-8"
        )
        record["proofs"] = {
            name: sha(folder / name) for name in (role + "-trivy.json", role + "-sbom.json")
        }
        binding["images"][role] = record
    binding["database"] = load(cache / "db/metadata.json")
    (folder / "supply-chain.json").write_text(
        json.dumps(binding, indent=2) + "\n", encoding="utf-8"
    )
    verify(folder, archives, inspect=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scan", "verify", "load"))
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    if args.command == "scan":
        if args.cache is None:
            raise ValueError("Explicit disposable scanner cache required")
        scan(args.folder, args.archives, args.cache)
    elif args.command == "load":
        verify(args.folder, args.archives)
        images = load(args.folder / "images.json")
        for role in ROLES:
            command(
                ["docker", "load", "--input", str(args.archives / images[role]["archive_name"])],
                timeout=300,
            )
        verify(args.folder, args.archives, inspect=True)
    else:
        verify(args.folder, args.archives, inspect=True)
    print("Dual-image dependency/CVE/SBOM admission verified; no production authority")


if __name__ == "__main__":
    main()
