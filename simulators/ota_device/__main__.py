from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
import time
from collections.abc import Generator
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx2 as httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connected_vehicle.ota.artifacts import verify_signature
from connected_vehicle.ota.device_proof import proof_headers
from connected_vehicle.ota.execution_contracts import ClaimResult
from simulators.ota_device.store import DeviceStore, exclusive


class ECUAuth(httpx.Auth):
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        raw = args.ecu_private_key.read_bytes()
        if len(raw) > 4096:
            raise ValueError("Oversized ECU key")
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("ECU proof requires Ed25519")
        self.key = key

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers.update(
            proof_headers(
                self.key,
                method=request.method,
                path=request.url.path,
                body=request.content,
                tenant=self.args.tenant,
                vehicle=self.args.vehicle,
                ecu=self.args.ecu,
                device=self.args.device_id,
                nonce=str(uuid4()),
                timestamp=str(int(time.time())),
            )
        )
        yield request


def request(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    json: object = None,
    content: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    for attempt in range(3):
        try:
            response = client.request(method, path, json=json, content=content, headers=headers)
            if response.status_code in {401, 403}:
                raise PermissionError("Device authentication is blocked; retain pending reports")
            if response.status_code < 500:
                if response.status_code != 200:
                    raise RuntimeError("OTA request rejected: " + str(response.status_code))
                return response
        except httpx.HTTPError:
            if attempt == 2:
                raise
        if attempt < 2:
            time.sleep(0.1 * 2**attempt)
    raise RuntimeError("Bounded OTA retries exhausted")


def sync_directory(directory: Path) -> None:
    if sys.platform != "win32":
        handle = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)


def download(client: httpx.Client, path: str, root: Path, claim: ClaimResult) -> None:
    images = root / "images"
    if images.is_symlink():
        raise ValueError("Unsafe bank directory")
    images.mkdir(exist_ok=True)
    target = images / (claim.manifest.sha256 + ".bin")
    if target.exists():
        if target.is_symlink() or target.stat().st_size != claim.manifest.size_bytes:
            raise ValueError("Existing bank integrity mismatch")
        with target.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != claim.manifest.sha256:
                raise ValueError("Existing bank integrity mismatch")
        return
    partial = images / (str(claim.job.id) + ".part")
    if partial.is_symlink():
        raise ValueError("Unsafe staging path")
    digest, size = hashlib.sha256(), 0
    with client.stream(
        "GET", path + "/artifact", headers={"X-OTA-Claim": str(claim.claim_token)}
    ) as response:
        if response.status_code in {401, 403}:
            raise PermissionError("Artifact authentication blocked")
        if response.status_code != 200:
            raise RuntimeError("Artifact download rejected")
        with partial.open("wb") as stream:
            for chunk in response.iter_bytes(chunk_size=65536):
                size += len(chunk)
                if size > claim.manifest.size_bytes:
                    raise ValueError("Oversized firmware download")
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
    if size != claim.manifest.size_bytes or digest.hexdigest() != claim.manifest.sha256:
        raise ValueError("Downloaded bytes do not match the signed manifest")
    os.replace(partial, target)
    sync_directory(images)


def run(args: argparse.Namespace) -> dict[str, object]:
    url = urlsplit(args.base_url)
    if (
        url.scheme != "http"
        or url.hostname not in {"127.0.0.1", "localhost", "::1"}
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
    ):
        raise ValueError("Day18 simulator requires a loopback local API")
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token or len(token) > 16384:
        raise ValueError("Invalid token file")
    with exclusive(args.state_dir):
        store = DeviceStore(
            args.state_dir,
            tenant=args.tenant,
            vehicle=args.vehicle,
            ecu=args.ecu,
            device=args.device_id,
            ecu_type=args.ecu_type,
            hardware_version=args.hardware_version,
        )
        try:
            with httpx.Client(
                base_url=args.base_url,
                headers={"Authorization": "Bearer " + token},
                auth=ECUAuth(args),
                timeout=3,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                if args.job is None:
                    args.job = store.unfinished()
                    if args.job is None:
                        available = request(
                            client,
                            "GET",
                            f"/v2/vehicles/{args.vehicle}/ecus/{args.ecu}/ota-jobs/next",
                        ).json()
                        if not available:
                            return dict(
                                status="idle",
                                active=store.active(),
                                pending_reports=0,
                                simulated_installation=True,
                            )
                        args.job = available[0]["id"]
                operation = store.prepare(args.job)
                path = f"/v2/vehicles/{args.vehicle}/ecus/{args.ecu}/ota-jobs/{args.job}"
                response = request(
                    client, "POST", path + "/claim", json={"operation_id": operation}
                )
                claim = ClaimResult.model_validate_json(response.content)
                if str(claim.job.id) != args.job or claim.manifest.size_bytes > 32 * 1024**2:
                    raise ValueError("Unexpected or oversized job")
                verify_signature(args.trusted_keys, claim.manifest, claim.signature)
                store.accept(claim)
                active = store.active()
                if (
                    active
                    and active["job_id"] != args.job
                    and claim.manifest.security_version <= int(str(active["security_version"]))
                ):
                    raise ValueError("Device anti-rollback floor rejected the job")
                if store.state(args.job) == "claimed":
                    download(client, path, args.state_dir, claim)
                    store.downloaded(args.job)
                    if args.crash_at == "after_download":
                        os._exit(86)

                def deliver() -> None:
                    for event, payload in store.pending(args.job):
                        report = request(
                            client,
                            "POST",
                            path + "/reports",
                            content=payload,
                            headers={"Content-Type": "application/json"},
                        )
                        if args.crash_at == "after_terminal_ack" and report.json()["status"] in {
                            "succeeded",
                            "failed",
                        }:
                            os._exit(88)
                        store.delivered(event)

                if store.state(args.job) == "downloaded":
                    store.installing(claim)
                deliver()
                if store.state(args.job) == "installing":
                    image = args.state_dir / "images" / (claim.manifest.sha256 + ".bin")
                    with image.open("rb") as stream:
                        healthy = stream.read(7) == b"CVOTA1\n" and not args.fail_health_check
                    verify_signature(args.trusted_keys, claim.manifest, claim.signature)
                    store.activate(claim, healthy=healthy)
                    if args.crash_at == "after_install":
                        os._exit(87)
                deliver()
            return dict(
                status=store.state(args.job),
                active=store.active(),
                pending_reports=len(store.pending(args.job)),
                simulated_installation=True,
            )
        finally:
            store.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Day18 local OTA bank simulator; loopback only")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--vehicle", required=True)
    parser.add_argument("--ecu", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--ecu-type", required=True)
    parser.add_argument("--hardware-version", required=True)
    parser.add_argument("--job", help="Omit to resume persisted work or poll a verified job")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    parser.add_argument(
        "--ecu-private-key",
        type=Path,
        required=True,
        help="Independent ECU installation proof key; never supplied by API",
    )
    parser.add_argument(
        "--crash-at", choices=("after_download", "after_install", "after_terminal_ack")
    )
    parser.add_argument("--fail-health-check", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args)
    except (ValueError, OSError, RuntimeError, sqlite3.Error, httpx.HTTPError) as exc:
        print("OTA simulator stopped: " + type(exc).__name__, file=sys.stderr)
        return 1
    import json

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
