from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.day41_rotation import CHECKS, SEQUENCE, Journal, Phase, Scope


def scope(kind: str = "redis") -> Scope:
    path = "redis/auth" if kind == "redis" else "database/application"
    return Scope(
        "123456789012",
        "ap-northeast-1",
        kind,
        f"arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:/connected-vehicle/staging/{path}-abc123",
        "a" * 32,
    )


def advance(
    journal: Journal, item: Scope, before: Phase, after: Phase, digest: str = "b" * 64
) -> None:
    checks = dict.fromkeys(CHECKS.get(after, set()), True)
    if item.kind == "redis" and after == Phase.TARGET_UPDATED:
        checks["old_and_new_tls_login"] = True
    if item.kind == "postgres" and after == Phase.PENDING_TESTED:
        checks["rls_and_grants_unchanged"] = True
    journal.record(item, before, after, item, checks, digest)


@pytest.mark.parametrize("kind", ["redis", "postgres"])
def test_verified_sequence_allows_a_later_operation(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "journal.db"
    item = scope(kind)
    for before, after in zip(SEQUENCE[:-1], SEQUENCE[1:], strict=True):
        advance(Journal(path), item, before, after)
    advance(Journal(path), replace(item, version="c" * 32), Phase.REQUESTED, Phase.PENDING_CREATED)


def test_interruption_is_persistent_and_blocks_other_credential(tmp_path: Path) -> None:
    path = tmp_path / "journal.db"
    item = scope()
    advance(Journal(path), item, Phase.REQUESTED, Phase.PENDING_CREATED)
    advance(Journal(path), item, Phase.PENDING_CREATED, Phase.BLOCKED)
    with pytest.raises(ValueError, match="unresolved"):
        advance(Journal(path), scope("postgres"), Phase.REQUESTED, Phase.PENDING_CREATED)
    with pytest.raises(ValueError, match="Terminal"):
        advance(Journal(path), item, Phase.BLOCKED, Phase.VERIFIED)


def test_retirement_cannot_skip_client_replacement(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "journal.db")
    item = scope()
    for before, after in zip(SEQUENCE[:4], SEQUENCE[1:5], strict=True):
        advance(journal, item, before, after)
    with pytest.raises(ValueError, match="out-of-order"):
        advance(journal, item, Phase.SECRET_PROMOTED, Phase.OLD_RETIRED)
    checks = dict.fromkeys(CHECKS[Phase.CLIENTS_REFRESHED], True)
    checks["outbox"] = False
    with pytest.raises(ValueError, match="out-of-order"):
        journal.record(item, Phase.SECRET_PROMOTED, Phase.CLIENTS_REFRESHED, item, checks, "a" * 64)


def test_unknown_acknowledgement_allows_only_exact_observation_replay(tmp_path: Path) -> None:
    path = tmp_path / "journal.db"
    item = scope()
    for _ in range(2):
        advance(Journal(path), item, Phase.REQUESTED, Phase.PENDING_CREATED)
    with pytest.raises(ValueError, match="Stale"):
        advance(Journal(path), item, Phase.REQUESTED, Phase.PENDING_CREATED, "d" * 64)
    with pytest.raises(ValueError, match="Unbound"):
        Journal(path).record(
            item,
            Phase.PENDING_CREATED,
            Phase.BLOCKED,
            replace(item, version="d" * 32),
            {},
            "a" * 64,
        )


def test_sqlite_serializes_competing_credentials(tmp_path: Path) -> None:
    journal = Journal(tmp_path / "journal.db")

    def start(item: Scope) -> bool:
        try:
            advance(journal, item, Phase.REQUESTED, Phase.PENDING_CREATED)
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(start, [scope(), scope("postgres")])) == [False, True]
