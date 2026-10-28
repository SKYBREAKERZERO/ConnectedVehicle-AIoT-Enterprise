from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from scripts.iac.deploy_governance import ROOT, run_identity
from scripts.iac.plan_admission import canonical_digest
from scripts.iac.state_integrity import recovery_errors, state_errors

NOW = datetime(2026, 10, 28, 8, tzinfo=UTC)


@pytest.fixture(scope="module", autouse=True)
def stamp_day28(record_testsuite_property: Callable[[str, object], None]) -> None:
    from scripts.iac.day28_evidence import source_digest

    for key, value in {
        "day28_commit": os.environ.get("GITHUB_SHA")
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "day28_run_id": run_identity(),
        "day28_source_sha256": source_digest(),
    }.items():
        record_testsuite_property(key, value)


def sample() -> tuple[bytes, dict[str, Any]]:
    raw = json.dumps(
        {
            "version": 4,
            "terraform_version": "1.14.7",
            "serial": 9,
            "lineage": "11111111-2222-3333-4444-555555555555",
            "outputs": {},
            "resources": [],
        }
    ).encode()
    return raw, {
        "account": "000000000000",
        "environment": "local",
        "bucket": "cv-test-state",
        "key": "ota/local/terraform.tfstate",
        "version_id": "reviewed-version-9",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "serial": 9,
        "lineage": "11111111-2222-3333-4444-555555555555",
        "commit": "a" * 40,
        "run_id": "12345:1",
    }


def test_reviewed_state_integrity_passes_without_granting_restore() -> None:
    raw, record = sample()
    assert state_errors(raw, observed=record, expected=record, authenticate=lambda _: True) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lineage", "22222222-2222-2222-2222-222222222222"),
        ("serial", 8),
        ("serial", 10),
        ("serial", True),
        ("version_id", "old-version"),
        ("sha256", "b" * 64),
        ("environment", "production"),
        ("account", "999999999999"),
        ("bucket", "other-bucket"),
        ("key", "ota/production/terraform.tfstate"),
        ("commit", "b" * 40),
        ("run_id", "12345:2"),
    ],
)
def test_changed_state_identity_or_version_is_denied(field: str, value: Any) -> None:
    raw, record = sample()
    observed = {**record, field: value}
    assert state_errors(raw, observed=observed, expected=record, authenticate=lambda _: True)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        b"",
        b"{corrupt",
        b"null",
        b'{"version":4,"version":4}',
        b'{"serial":NaN}',
        b'{"version":4,"serial":true,"outputs":{},"resources":[]}',
    ],
)
def test_missing_corrupt_or_duplicate_state_is_denied(raw: bytes | None) -> None:
    _, record = sample()
    # Even a matching hash does not authorize malformed structure.
    if raw:
        record["sha256"] = hashlib.sha256(raw).hexdigest()
    assert state_errors(raw, observed=record, expected=record, authenticate=lambda _: True)


@pytest.mark.parametrize("authority", [False, None, 1])
def test_hash_alone_cannot_replace_trusted_version_authority(authority: Any) -> None:
    raw, record = sample()
    assert state_errors(raw, observed=record, expected=record, authenticate=lambda _: authority)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("serial", 8),
        ("serial", 10),
        ("serial", True),
        ("lineage", "22222222-2222-2222-2222-222222222222"),
        ("version", 4.0),
    ],
)
def test_payload_lineage_and_serial_must_match_the_trusted_record(field: str, value: Any) -> None:
    raw, record = sample()
    data = json.loads(raw)
    data[field] = value
    raw = json.dumps(data).encode()
    record["sha256"] = hashlib.sha256(raw).hexdigest()
    assert state_errors(raw, observed=record, expected=record, authenticate=lambda _: True)


def test_local_marker_cannot_authorize_a_production_record() -> None:
    raw, record = sample()
    record["run_id"] = "local:1"
    assert not state_errors(raw, observed=record, expected=record, authenticate=lambda _: True)
    record.update(
        environment="production", account="123456789012", key="ota/production/terraform.tfstate"
    )
    assert state_errors(raw, observed=record, expected=record, authenticate=lambda _: True)


def recovery_args() -> dict[str, Any]:
    _, record = sample()
    active = {k: record[k] for k in ("account", "environment", "bucket", "key")}
    target = {**active, "bucket": "cv-isolated-copy", "disposable": True}
    approval = {
        "binding_sha256": canonical_digest({"record": record, "active": active, "target": target}),
        "reviewer": "independent-reviewer",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "recovery_id": "recovery-1",
    }
    return {
        "record": record,
        "active": active,
        "target": target,
        "approval": approval,
        "actor": "requester",
        "now": NOW,
        "lock_present": False,
        "authenticate": lambda _: True,
    }


def test_only_reviewed_isolated_recovery_copy_is_admissible() -> None:
    assert recovery_errors(**recovery_args()) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "self",
        "expired",
        "revoked",
        "lock",
        "same-backend",
        "production",
        "not-disposable",
        "version",
        "run",
        "target",
        "missing-record",
        "authority-error",
    ],
)
def test_recovery_never_auto_restores_active_or_unreviewed_state(mutation: str) -> None:
    args = deepcopy(recovery_args())
    if mutation == "self":
        args["approval"]["reviewer"] = "REQUESTER"
    if mutation == "expired":
        args["approval"]["expires_at"] = NOW.isoformat()
    if mutation == "revoked":
        args["authenticate"] = lambda _: False
    if mutation == "lock":
        args["lock_present"] = True
    if mutation == "same-backend":
        args["target"]["bucket"] = args["active"]["bucket"]
    if mutation == "production":
        args["target"]["environment"] = "production"
    if mutation == "not-disposable":
        args["target"]["disposable"] = False
    if mutation == "version":
        args["record"]["version_id"] = "another-version"
    if mutation == "run":
        args["record"]["run_id"] = "99999:1"
    if mutation == "target":
        args["target"]["key"] = "other.tfstate"
    if mutation == "missing-record":
        del args["record"]["sha256"]
    if mutation == "authority-error":

        def unavailable(_: Any) -> bool:
            raise OSError("authority unavailable")

        args["authenticate"] = unavailable
    assert recovery_errors(**args)
