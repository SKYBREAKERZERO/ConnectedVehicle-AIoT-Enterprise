"""Local registry contracts; fixtures deliberately simulate an identity adapter."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from scripts.iac.trusted_state_registry import TrustedStateRegistry

NOW = datetime(2026, 10, 29, 8, tzinfo=UTC)
SOURCE = {
    "account": "123456789012",
    "environment": "production",
    "bucket": "cv-source-state",
    "key": "ota/production/terraform.tfstate",
}
TARGET = {**SOURCE, "bucket": "cv-recovered-state"}
LINEAGE = "11111111-2222-3333-4444-555555555555"


@dataclass
class FakeClock:
    now: datetime = NOW

    def __call__(self) -> datetime:
        return self.now


def fake_identity(actor: str, action: str, digest: str) -> bool:
    return (
        actor in {"publisher", "requester", "reviewer", "reviewer-two", "other-requester"}
        and bool(action)
        and len(digest) == 64
    )


def state(
    scope: dict[str, Any] | None = None,
    *,
    serial: int = 9,
    version: str = "state-v9",
    lineage: str = LINEAGE,
    commit: str = "a" * 40,
    run_id: str = "111:1",
) -> tuple[bytes, dict[str, Any]]:
    raw = json.dumps(
        {
            "version": 4,
            "terraform_version": "1.14.7",
            "serial": serial,
            "lineage": lineage,
            "outputs": {},
            "resources": [],
        }
    ).encode()
    return raw, {
        **(SOURCE if scope is None else scope),
        "version_id": version,
        "serial": serial,
        "lineage": lineage,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "commit": commit,
        "run_id": run_id,
    }


def registry(path: Path, scope: dict[str, Any] | None = None) -> TrustedStateRegistry:
    return TrustedStateRegistry(
        path,
        scope=SOURCE if scope is None else scope,
        registrars=frozenset({"publisher"}),
        authenticate=fake_identity,
    )


def test_registered_head_survives_reopen_and_scope_return_is_not_mutable_policy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "governance.sqlite"
    store = registry(path)
    raw, record = state()
    store.register(raw, record, actor="publisher")
    registry(path).verify(raw, record)
    copy = store.scope
    copy["account"] = "999999999999"
    assert store.scope == SOURCE


def test_matching_hash_with_an_unregistered_version_is_rejected(tmp_path: Path) -> None:
    store = registry(tmp_path / "governance.sqlite")
    raw, record = state()
    store.register(raw, record, actor="publisher")
    with pytest.raises(ValueError):
        store.verify(raw, {**record, "version_id": "not-registered"})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account", "999999999999"),
        ("environment", "local"),
        ("lineage", "22222222-2222-2222-2222-222222222222"),
        ("serial", 8),
        ("serial", 10),
        ("serial", True),
        ("sha256", "b" * 64),
        ("commit", "b" * 40),
        ("run_id", "111:2"),
        ("key", "other.tfstate"),
    ],
)
def test_registry_rejects_cross_scope_or_substituted_metadata(
    tmp_path: Path, field: str, value: Any
) -> None:
    store = registry(tmp_path / "governance.sqlite")
    raw, record = state()
    store.register(raw, record, actor="publisher")
    with pytest.raises(ValueError):
        store.verify(raw, {**record, field: value})


@pytest.mark.parametrize("answer", [False, None, 1])
def test_unverified_publisher_cannot_register(tmp_path: Path, answer: Any) -> None:
    store = TrustedStateRegistry(
        tmp_path / "governance.sqlite",
        scope=SOURCE,
        registrars=frozenset({"publisher"}),
        authenticate=lambda *_: answer,
    )
    raw, record = state()
    with pytest.raises(ValueError):
        store.register(raw, record, actor="publisher")
    assert not store.is_current(record)


def test_allowlist_still_denies_unknown_publisher_even_if_adapter_says_true(tmp_path: Path) -> None:
    store = TrustedStateRegistry(
        tmp_path / "governance.sqlite",
        scope=SOURCE,
        registrars=frozenset({"publisher"}),
        authenticate=lambda *_: True,
    )
    raw, record = state()
    with pytest.raises(ValueError):
        store.register(raw, record, actor="attacker")
    with pytest.raises(ValueError):
        store.register(b"corrupt", record, actor="publisher")


def test_head_progression_is_monotonic_and_revocation_never_falls_back(tmp_path: Path) -> None:
    store = registry(tmp_path / "governance.sqlite")
    raw, old = state()
    store.register(raw, old, actor="publisher")
    new_raw, new = state(serial=10, version="state-v10")
    store.register(new_raw, new, actor="publisher")
    with pytest.raises(ValueError):
        store.verify(raw, old)
    store.revoke(new, actor="publisher")
    assert not store.is_current(old) and not store.is_current(new)
    with pytest.raises(ValueError):
        store.register(raw, {**old, "version_id": "another-old"}, actor="publisher")


@pytest.mark.parametrize(
    "case", ["serial-equal", "serial-rollback", "new-lineage", "reuse-version-id"]
)
def test_registry_rejects_reset_and_immutable_version_replacement(
    tmp_path: Path, case: str
) -> None:
    store = registry(tmp_path / "governance.sqlite")
    raw, record = state()
    store.register(raw, record, actor="publisher")
    kwargs: dict[str, Any] = {"serial": 10, "version": "state-v10"}
    if case == "serial-equal":
        kwargs["serial"] = 9
    if case == "serial-rollback":
        kwargs["serial"] = 8
    if case == "new-lineage":
        kwargs["lineage"] = "22222222-2222-2222-2222-222222222222"
    if case == "reuse-version-id":
        kwargs["version"] = "state-v9"
    new_raw, new = state(**kwargs)
    with pytest.raises(ValueError):
        store.register(new_raw, new, actor="publisher")
    store.verify(raw, record)


@pytest.mark.parametrize("table", ["vehicles", "events", "releases"])
def test_business_database_and_silent_policy_changes_are_rejected(
    tmp_path: Path, table: str
) -> None:
    business = tmp_path / "business.sqlite"
    with sqlite3.connect(business) as connection:
        connection.execute(f"CREATE TABLE {table}(id INTEGER)")
    with pytest.raises(ValueError, match="business"):
        registry(business)
    with sqlite3.connect(business) as connection:
        assert {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        } == {table}
    path = tmp_path / "governance.sqlite"
    registry(path)
    with pytest.raises(ValueError, match="policy changed"):
        TrustedStateRegistry(
            path, scope=SOURCE, registrars=frozenset({"attacker"}), authenticate=lambda *_: True
        )


def test_inconsistent_stored_record_is_not_authenticated(tmp_path: Path) -> None:
    path = tmp_path / "governance.sqlite"
    store = registry(path)
    raw, record = state()
    store.register(raw, record, actor="publisher")
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE day29_versions SET record='{}'")
    assert not store.is_current(record)
