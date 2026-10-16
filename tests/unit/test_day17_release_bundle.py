from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.day16_evidence import provenance
from scripts.day17_release import (
    OTA_CHECKS,
    evaluate,
    readiness_digest,
    verify_artifact,
    verify_readiness,
    write_json,
)
from tests.unit.test_day16_evidence import seed
from tests.unit.test_day17_readiness import window


def bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(tmp_path, monkeypatch)
    from scripts.day16_evidence import verify

    verify(tmp_path)
    write_json(
        tmp_path / "day17-ota-foundation.json",
        dict(
            version=1,
            profile="local_drill",
            provenance=provenance(),
            checks={key: True for key in sorted(OTA_CHECKS)},
            generated_at_utc=datetime.now(UTC).isoformat(),
            real_aws_verified=False,
            device_execution_verified=False,
        ),
    )
    fault = window(failures=5, age=2).model_copy(update={"phase": "fault"})
    recovered = window().model_copy(update={"window_id": "b" * 32})
    write_json(
        tmp_path / "day17-canary.json",
        dict(
            version=1,
            profile="local_drill",
            provenance=provenance(),
            readiness_sha256=readiness_digest(),
            fault=fault.model_dump(mode="json"),
            recovered=recovered.model_dump(mode="json"),
            connection_limit_restored=True,
            runtime_superuser=False,
            runtime_bypassrls=False,
            runtime_schema_create=False,
            real_aws_verified=False,
        ),
    )


def test_readiness_bundle_replays_without_overwriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle(tmp_path, monkeypatch)
    decision = evaluate(tmp_path)
    assert decision["decision"] == "ready_for_local_release"
    write_json(tmp_path / "day17-readiness.json", decision)
    assert verify_readiness(tmp_path) == decision
    with pytest.raises(ValueError, match="expired"):
        evaluate(tmp_path, now=datetime.now(UTC) + timedelta(seconds=901))


@pytest.mark.parametrize(
    "case",
    [
        "source",
        "policy",
        "superuser",
        "missing_fault",
        "metrics",
        "day16",
        "manifest",
        "future",
        "ota_missing",
        "ota_failed",
    ],
)
def test_release_rejects_inconsistent_or_missing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    bundle(tmp_path, monkeypatch)
    decision = evaluate(tmp_path)
    write_json(tmp_path / "day17-readiness.json", decision)
    path = tmp_path / "day17-canary.json"
    record = json.loads(path.read_text())
    if case == "source":
        record["provenance"]["source_sha256"] = "0" * 64
    elif case == "policy":
        record["readiness_sha256"] = "1" * 64
    elif case == "superuser":
        record["runtime_superuser"] = True
    elif case == "missing_fault":
        record["fault"] = record["recovered"]
    elif case == "metrics":
        record["recovered"]["metrics_delta"]["requests"] = 99
    elif case == "future":
        record["recovered"]["ended_at"] = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
    elif case == "day16":
        (tmp_path / "day16-outbox-crash.json").unlink()
    elif case == "ota_missing":
        (tmp_path / "day17-ota-foundation.json").unlink()
    elif case == "ota_failed":
        ota_path = tmp_path / "day17-ota-foundation.json"
        ota = json.loads(ota_path.read_text())
        ota["checks"]["cross_tenant_api_denied"] = False
        ota_path.write_text(json.dumps(ota))
    else:
        result = json.loads((tmp_path / "day17-readiness.json").read_text())
        result["decision"] = "abort"
        (tmp_path / "day17-readiness.json").write_text(json.dumps(result))
    path.write_text(json.dumps(record))
    with pytest.raises((ValueError, FileNotFoundError)):
        verify_readiness(tmp_path)


@pytest.mark.parametrize("case", ["valid", "bytes", "digest", "head", "run", "expired", "missing"])
def test_actions_archive_binding(case: str) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as package:
        package.writestr("day17-readiness.json", b'{"decision":"ready"}')
    archive = stream.getvalue()
    head = "a" * 40
    metadata = {
        "id": 123,
        "name": "day17-local-readiness",
        "expired": case == "expired",
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "workflow_run": {"id": 456, "head_sha": head},
    }
    if case == "digest":
        metadata["digest"] = "sha256:" + "0" * 64
    expected = {"day17-readiness.json": b'{"decision":"ready"}'}
    if case == "bytes":
        expected["day17-readiness.json"] = b'{"decision":"forged"}'
    elif case == "missing":
        expected["missing.json"] = b"{}"
    if case == "valid":
        assert verify_artifact(archive, metadata, expected, head=head, run_id=456)["id"] == 123
    else:
        with pytest.raises(ValueError):
            verify_artifact(
                archive,
                metadata,
                expected,
                head="b" * 40 if case == "head" else head,
                run_id=789 if case == "run" else 456,
            )
