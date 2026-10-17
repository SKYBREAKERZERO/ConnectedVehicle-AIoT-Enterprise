"""Bounded, version-pinned S3 reads and tenant-scoped offline trust roots."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import tempfile
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, BinaryIO, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from connected_vehicle.ota.execution_contracts import SignedManifest
from connected_vehicle.ota.publisher_keys import public_key
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
    try:
        public = public_key(path, manifest.tenant_id, manifest.key_id)
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(signature, validate=True), manifest.canonical()
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ValueError("Untrusted OTA signature") from exc


class S3Reader(Protocol):
    def get_object(self, **kwargs: object) -> dict[str, Any]: ...


class ArtifactHandle:
    def __init__(self, stream: BinaryIO, size: int, capacity: asyncio.Semaphore) -> None:
        self.stream, self.size, self.capacity = stream, size, capacity
        self.closed = False

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.stream.close()
            finally:
                self.capacity.release()

    async def aclose(self) -> None:
        self.close()

    async def chunks(self) -> AsyncIterator[bytes]:
        try:
            while block := self.stream.read(65536):
                yield block
                await asyncio.sleep(0)
        finally:
            self.close()


class ArtifactVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # At most two validated files/responses, each bounded by the configured size.
        self.capacity = asyncio.Semaphore(2)

    async def fetch_file(self, manifest: SignedManifest, signature: str) -> ArtifactHandle:
        if not self.settings.ota_trusted_keys_file:
            raise ConflictError("OTA trust roots are not configured.")
        try:
            verify_signature(Path(self.settings.ota_trusted_keys_file), manifest, signature)
        except (OSError, ValueError) as exc:
            raise ConflictError("OTA signature verification failed.") from exc
        if manifest.size_bytes > self.settings.ota_max_artifact_bytes:
            raise ConflictError("Artifact exceeds configured quota.")
        try:
            await asyncio.wait_for(
                self.capacity.acquire(), timeout=self.settings.ota_artifact_timeout_seconds
            )
        except TimeoutError as exc:
            raise DependencyUnavailableError("OTA transfer capacity exhausted.") from exc
        work = asyncio.create_task(asyncio.to_thread(self.read_file, manifest))
        try:
            stream = await asyncio.shield(work)
            return ArtifactHandle(stream, manifest.size_bytes, self.capacity)
        except asyncio.CancelledError:
            try:
                stream = await work
                stream.close()
            finally:
                self.capacity.release()
            raise
        except (ValueError, TimeoutError) as exc:
            self.capacity.release()
            raise ConflictError("OTA artifact integrity/deadline validation failed.") from exc
        except Exception as exc:
            self.capacity.release()
            raise DependencyUnavailableError("Pinned firmware object unavailable.") from exc

    async def fetch(self, manifest: SignedManifest, signature: str) -> bytes:
        handle = await self.fetch_file(manifest, signature)
        try:
            return handle.stream.read()
        finally:
            handle.close()

    def read_file(self, manifest: SignedManifest) -> BinaryIO:
        deadline = time.monotonic() + self.settings.ota_artifact_timeout_seconds
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
        result = cast(BinaryIO, tempfile.TemporaryFile(mode="w+b"))  # noqa: SIM115 -- Ownership transfers to ArtifactHandle; every error closes it below.
        try:
            if (
                response.get("VersionId") != manifest.artifact_version
                or response["ContentLength"] != manifest.size_bytes
            ):
                raise ValueError("Pinned object version/size mismatch")
            size = 0
            checksum = hashlib.sha256()
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("Artifact deadline exceeded before read")
                chunk = body.read(min(65536, manifest.size_bytes + 1 - size))
                if time.monotonic() > deadline:
                    raise TimeoutError("Artifact deadline exceeded after read")
                if not chunk:
                    break
                size += len(chunk)
                if size > manifest.size_bytes:
                    raise ValueError("Object exceeded quota")
                result.write(chunk)
                checksum.update(chunk)
            if size != manifest.size_bytes or checksum.hexdigest() != manifest.sha256:
                raise ValueError("Object checksum mismatch")
            result.seek(0)
            return result
        except BaseException:
            result.close()
            raise
        finally:
            body.close()
