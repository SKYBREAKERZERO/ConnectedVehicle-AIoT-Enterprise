"""Bounded, version-pinned S3 reads and tenant-scoped offline trust roots."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from connected_vehicle.ota.execution_contracts import SignedManifest
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.errors.base import ConflictError, DependencyUnavailableError


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate trust-store key")
        result[key] = value
    return result


def verify_signature(path: Path, manifest: SignedManifest, signature: str) -> None:
    with path.open("rb") as stream:
        encoded = stream.read(65537)
    if len(encoded) > 65536:
        raise ValueError("Oversized trust store")
    keys = json.loads(encoded, object_pairs_hook=unique_pairs)
    try:
        public = base64.b64decode(keys[manifest.tenant_id][manifest.key_id], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(signature, validate=True), manifest.canonical()
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ValueError("Untrusted OTA signature") from exc


class S3Reader(Protocol):
    def get_object(self, **kwargs: object) -> dict[str, Any]: ...


class ArtifactVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.capacity = asyncio.Semaphore(2)

    async def fetch(self, manifest: SignedManifest, signature: str) -> bytes:
        if not self.settings.ota_trusted_keys_file:
            raise ConflictError("OTA trust roots are not configured.")
        try:
            verify_signature(Path(self.settings.ota_trusted_keys_file), manifest, signature)
        except (OSError, ValueError) as exc:
            raise ConflictError("OTA signature verification failed.") from exc
        if manifest.size_bytes > self.settings.ota_max_artifact_bytes:
            raise ConflictError("Artifact exceeds the configured local execution limit.")
        async with self.capacity:
            try:
                work = asyncio.create_task(asyncio.to_thread(self.read, manifest))
                try:
                    return await asyncio.shield(work)
                except asyncio.CancelledError:
                    with suppress(Exception):
                        await work
                    raise
            except (ValueError, TimeoutError) as exc:
                raise ConflictError("OTA artifact integrity verification failed.") from exc
            except Exception as exc:
                raise DependencyUnavailableError("Pinned firmware object is unavailable.") from exc

    def read(self, manifest: SignedManifest) -> bytes:
        client = cast(
            S3Reader,
            AWSClientFactory(
                self.settings.model_copy(
                    update={
                        "aws_max_attempts": 1,
                        "aws_connect_timeout_seconds": 2.0,
                        "aws_read_timeout_seconds": 3.0,
                    }
                )
            ).s3(),
        )
        response = client.get_object(
            Bucket=manifest.artifact_bucket,
            Key=manifest.artifact_key,
            VersionId=manifest.artifact_version,
        )
        body = response["Body"]
        try:
            if (
                response.get("VersionId") != manifest.artifact_version
                or response["ContentLength"] != manifest.size_bytes
            ):
                raise ValueError("Pinned version/size mismatch")
            deadline = time.monotonic() + self.settings.ota_artifact_timeout_seconds
            result = bytearray()
            checksum = hashlib.sha256()
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("Artifact deadline exceeded")
                chunk = body.read(min(65536, manifest.size_bytes + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                checksum.update(chunk)
                if len(result) > manifest.size_bytes:
                    raise ValueError("Oversized object stream")
            if len(result) != manifest.size_bytes or checksum.hexdigest() != manifest.sha256:
                raise ValueError("Object checksum mismatch")
            return bytes(result)
        finally:
            body.close()
