from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from database.credential_rotation import Target, restore, rotate
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import DATABASE_USERS
from tests.support.secret_versions import MemorySecrets


class Passwords:
    def __init__(self) -> None:
        self.values: dict[str, str | None] = dict.fromkeys(DATABASE_USERS.values())
        self.fail_verify = False
        self.fail_restore = False
        self.writes = 0

    async def has_password(self, role: str) -> bool:
        return self.values[role] is not None

    async def set_passwords(self, values: dict[str, str | None]) -> None:
        if self.fail_restore and any(
            value and value.startswith("old-") for value in values.values()
        ):
            raise RuntimeError("private recovery failure")
        self.writes += 1
        self.values.update(values)

    async def verify(self, target: Target, payload: dict[str, Any]) -> None:
        if self.fail_verify and payload["password"].startswith("new-"):
            raise RuntimeError("private validation failure")
        assert payload["username"] == target.role
        assert payload["password"] == self.values[target.role]


def setup(existing: bool) -> tuple[Settings, list[Target], MemorySecrets, Passwords]:
    settings = Settings.model_construct(credential_rotation_maintenance_mode=existing)
    targets = [
        Target(runtime, role, "/unit/" + runtime) for runtime, role in DATABASE_USERS.items()
    ]
    secrets, database = MemorySecrets(), Passwords()
    for target in targets:
        secrets.create_secret(Name=target.secret_id)
        if existing:
            value: dict[str, Any] = {
                "username": target.role,
                "password": "old-" + target.role,
                "host": settings.database_host,
                "port": settings.database_port,
                "dbname": settings.database_name,
            }
            secrets.put_secret_value(SecretId=target.secret_id, SecretString=json.dumps(value))
            database.values[target.role] = value["password"]
    secrets.calls.clear()
    return settings, targets, secrets, database


def candidates(targets: list[Target]) -> dict[str, str]:
    return {target.role: "new-" + target.role for target in targets}


@pytest.mark.parametrize("existing", [False, True])
async def test_publication_verifies_all_logins_and_keeps_journal_secret_free(
    tmp_path: Path, existing: bool
) -> None:
    settings, targets, secrets, database = setup(existing)
    path = await rotate(
        settings, targets, candidates(targets), secrets, database, directory=tmp_path
    )
    assert json.loads(path.read_text())["phase"] == "complete"
    for target in targets:
        assert secrets.current(target.secret_id) == {
            "engine": "postgres",
            "host": settings.database_host,
            "port": settings.database_port,
            "dbname": settings.database_name,
            "username": target.role,
            "password": "new-" + target.role,
        }
        assert database.values[target.role] == "new-" + target.role
        assert "new-" + target.role not in path.read_text()
        assert "old-" + target.role not in path.read_text()


@pytest.mark.parametrize("failure", ["prepare", "verify", "promote"])
async def test_failures_restore_every_password_and_current_version(
    tmp_path: Path, failure: str
) -> None:
    settings, targets, secrets, database = setup(True)
    original = {target.secret_id: secrets.current(target.secret_id) for target in targets}
    passwords = dict(database.values)
    if failure == "verify":
        database.fail_verify = True
    else:
        secrets.fail_method = (
            "put_secret_value" if failure == "prepare" else "update_secret_version_stage"
        )
        secrets.fail_call = 2
    with pytest.raises(RuntimeError, match="was recovered") as error:
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert "private" not in str(error.value) and "sensitive-candidate" not in str(error.value)
    assert database.values == passwords
    assert {target.secret_id: secrets.current(target.secret_id) for target in targets} == original
    assert json.loads(next(tmp_path.glob("*.json")).read_text())["phase"] == "recovered"


async def test_incomplete_compensation_requires_explicit_recovery(tmp_path: Path) -> None:
    settings, targets, secrets, database = setup(True)
    database.fail_verify = database.fail_restore = True
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))
    record = json.loads(path.read_text())
    assert record["phase"] == "recovery_required"
    database.fail_restore = False
    await restore(record, secrets, database, path)
    assert json.loads(path.read_text())["phase"] == "recovered"
    assert all(value == "old-" + role for role, value in database.values.items())


async def test_stale_recovery_cannot_overwrite_a_later_rotation(tmp_path: Path) -> None:
    settings, targets, secrets, database = setup(True)
    path = await rotate(
        settings, targets, candidates(targets), secrets, database, directory=tmp_path
    )
    record = json.loads(path.read_text())
    for target in targets:
        secrets.put_secret_value(SecretId=target.secret_id, SecretString='{"password":"later"}')
    before = dict(database.values)
    with pytest.raises(ValueError, match="superseded"):
        await restore(record, secrets, database, path)
    assert database.values == before


async def test_existing_rotation_requires_maintenance_and_recoverable_credentials(
    tmp_path: Path,
) -> None:
    settings, targets, secrets, database = setup(True)
    settings.credential_rotation_maintenance_mode = False
    with pytest.raises(ValueError, match="maintenance"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert database.writes == 0 and not list(tmp_path.iterdir())
    settings, targets, secrets, database = setup(False)
    database.values[targets[0].role] = "orphan-password"
    with pytest.raises(ValueError, match="recoverable"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert database.writes == 0


async def test_invalid_targets_and_duplicate_secrets_are_rejected(tmp_path: Path) -> None:
    settings, targets, secrets, database = setup(False)
    with pytest.raises(ValueError, match="identity"):
        await rotate(
            settings,
            [Target("outbox", "migration_owner", "/bad")],
            {"migration_owner": "new-password"},
            secrets,
            database,
            directory=tmp_path,
        )
    targets[1] = Target("outbox", "outbox_worker", targets[0].secret_id)
    with pytest.raises(ValueError, match="distinct"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert database.writes == 0


@pytest.mark.parametrize("failure", ["prepare", "verify"])
async def test_initial_partial_publication_restores_null_passwords_and_can_retry(
    tmp_path: Path, failure: str
) -> None:
    settings, targets, secrets, database = setup(False)
    if failure == "prepare":
        secrets.fail_method, secrets.fail_call = "put_secret_value", 2
    else:
        database.fail_verify = True
    with pytest.raises(RuntimeError, match="was recovered"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert all(value is None for value in database.values.values())
    assert all(secrets.current(target.secret_id) is None for target in targets)
    database.fail_verify = False
    secrets.fail_method = None
    path = await rotate(
        settings, targets, candidates(targets), secrets, database, directory=tmp_path
    )
    assert json.loads(path.read_text())["phase"] == "complete"
