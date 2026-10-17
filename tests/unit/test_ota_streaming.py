from __future__ import annotations

import asyncio
import hashlib
import io
import time
from pathlib import Path
from typing import Any

import pytest

from apps.api.routers.ota_execution import ArtifactResponse
from connected_vehicle.ota.artifacts import ArtifactHandle, ArtifactVerifier
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.errors.base import DependencyUnavailableError
from tests.unit.test_day18_ota import fixture_claim


class Body:
    def __init__(self, size: int) -> None:
        self.remaining = size
        self.closed = False

    def read(self, size: int) -> bytes:
        count = min(size, self.remaining)
        self.remaining -= count
        return b"x" * count

    def close(self) -> None:
        self.closed = True


def fake_client(monkeypatch: pytest.MonkeyPatch, manifest: Any, body_factory: Any) -> list[Body]:
    seen = []

    class Client:
        def get_object(self, **kwargs: object) -> dict[str, Any]:
            assert kwargs["VersionId"] == manifest.artifact_version
            body = body_factory()
            seen.append(body)
            return dict(
                Body=body, ContentLength=manifest.size_bytes, VersionId=manifest.artifact_version
            )

    monkeypatch.setattr(AWSClientFactory, "s3", lambda _: Client())
    return seen


def test_forty_mib_artifact_is_validated_to_file_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claim, _, _ = fixture_claim(tmp_path)
    count = 40 * 1024**2
    digest = hashlib.sha256()
    for _ in range(count // 65536):
        digest.update(b"x" * 65536)
    manifest = claim.manifest.model_copy(update={"size_bytes": count, "sha256": digest.hexdigest()})
    seen = fake_client(monkeypatch, manifest, lambda: Body(count))
    verifier = ArtifactVerifier(
        Settings.model_construct(
            ota_max_artifact_bytes=64 * 1024**2, ota_artifact_timeout_seconds=10
        )
    )
    with verifier.read_file(manifest) as stream:
        observed = hashlib.sha256()
        size = 0
        while block := stream.read(65536):
            size += len(block)
            assert len(block) <= 65536
            observed.update(block)
        assert size == count and observed.hexdigest() == manifest.sha256
    assert seen[0].closed


@pytest.mark.parametrize("late", ["last_data", "eof"])
def test_deadline_checked_after_last_data_and_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, late: str
) -> None:
    claim, _, _ = fixture_claim(tmp_path)
    manifest = claim.manifest.model_copy(
        update={"size_bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
    )
    clock = {"value": 0.0}

    class Slow(Body):
        def read(self, size: int) -> bytes:
            result = super().read(size)
            if (result and late == "last_data") or (not result and late == "eof"):
                clock["value"] = 2.0
            return result

    seen = fake_client(monkeypatch, manifest, lambda: Slow(1))
    monkeypatch.setattr(time, "monotonic", lambda: clock["value"])
    with pytest.raises(TimeoutError, match="after read"):
        ArtifactVerifier(Settings.model_construct(ota_artifact_timeout_seconds=1)).read_file(
            manifest
        )
    assert seen[0].closed


async def test_capacity_is_bounded_and_released_after_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claim, trust, data = fixture_claim(tmp_path)

    class Exact(Body):
        def read(self, size: int) -> bytes:
            offset = len(data) - self.remaining
            result = data[offset : offset + size]
            self.remaining -= len(result)
            return result

    seen = fake_client(monkeypatch, claim.manifest, lambda: Exact(len(data)))
    verifier = ArtifactVerifier(
        Settings.model_construct(ota_trusted_keys_file=str(trust), ota_artifact_timeout_seconds=1)
    )
    first = await verifier.fetch_file(claim.manifest, claim.signature)
    second = await verifier.fetch_file(claim.manifest, claim.signature)
    try:
        with pytest.raises(DependencyUnavailableError, match="capacity"):
            await verifier.fetch_file(claim.manifest, claim.signature)
        assert len(seen) == 2
        first.close()
        third = await asyncio.wait_for(verifier.fetch_file(claim.manifest, claim.signature), 2)
        third.close()
    finally:
        first.close()
        second.close()
    assert all(body.closed for body in seen)


async def test_slow_response_cancellation_closes_spool_and_releases_slot() -> None:
    capacity = asyncio.Semaphore(0)
    handle = ArtifactHandle(io.BytesIO(b"x"), 1, capacity)
    response = ArtifactResponse(handle, 0.02)

    async def send(message: Any) -> None:
        if message["type"] == "http.response.body":
            await asyncio.Event().wait()

    async def receive() -> dict[str, object]:
        await asyncio.Event().wait()
        return {"type": "http.disconnect"}

    with pytest.raises(TimeoutError):
        await response(
            {"type": "http", "method": "GET", "asgi": {"spec_version": "2.4"}}, receive, send
        )
    assert handle.stream.closed
    await asyncio.wait_for(capacity.acquire(), 0.1)
