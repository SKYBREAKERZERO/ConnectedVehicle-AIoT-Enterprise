from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from database.credential_journal import (
    CredentialPreflightError,
    database_target,
    environment_target,
)
from database.credential_rotation import Target, current_version, recover, restore, rotate
from database.provision_runtime_credentials import provision
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
        return self.values.get(role) is not None

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
    settings = Settings.model_construct(
        credential_rotation_maintenance_mode=existing,
        application_database_secret_id="/unit/application",
        outbox_database_secret_id="/unit/outbox",
        remote_command_database_secret_id="/unit/remote-command",
    )
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
    await restore(record, secrets, database, path, settings=settings)
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
        await restore(record, secrets, database, path, settings=settings)
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


async def test_explicit_recovery_failure_redacts_errors_and_retains_retry_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, targets, secrets, database = setup(True)
    database.fail_verify = database.fail_restore = True
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    path = next(tmp_path.glob("*.json"))

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    with pytest.raises(RuntimeError, match="recovery required") as failure:
        await recover(settings, path, secrets)
    assert "private" not in str(failure.value)
    assert failure.value.__suppress_context__ is True
    assert json.loads(path.read_text())["phase"] == "recovery_required"
    database.fail_restore = False
    await recover(settings, path, secrets)
    assert json.loads(path.read_text())["phase"] == "recovered"


async def unfinished(
    tmp_path: Path,
) -> tuple[Settings, list[Target], MemorySecrets, Passwords, Path]:
    settings, targets, secrets, database = setup(True)
    database.fail_verify = database.fail_restore = True
    with pytest.raises(RuntimeError, match="recovery required"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    database.fail_verify = database.fail_restore = False
    secrets.calls.clear()
    return settings, targets, secrets, database, next(tmp_path.glob("*.json"))


@pytest.mark.parametrize("missing", [0, 1, 2])
async def test_missing_secret_rejects_rotation_without_any_write(
    tmp_path: Path, missing: int
) -> None:
    settings, targets, secrets, database = setup(True)
    del secrets.values[targets[missing].secret_id]
    del secrets.labels[targets[missing].secret_id]
    before = deepcopy((secrets.values, secrets.labels, database.values, database.writes))
    with pytest.raises(CredentialPreflightError, match="Terraform"):
        await rotate(settings, targets, candidates(targets), secrets, database, directory=tmp_path)
    assert (secrets.values, secrets.labels, database.values, database.writes) == before
    assert not secrets.calls.get("create_secret") and not secrets.calls.get("put_secret_value")
    assert not list(tmp_path.iterdir())


async def test_existing_empty_secret_is_distinct_from_missing_resource() -> None:
    service = MemorySecrets()
    with pytest.raises(CredentialPreflightError, match="Terraform"):
        await current_version(service, "/missing")
    assert not service.values and not service.calls.get("create_secret")
    service.create_secret(Name="/empty")
    assert await current_version(service, "/empty") is None


STATIC_CASES = [
    "root_list",
    "root_null",
    "legacy_version",
    "float_version",
    "string_version",
    "bool_version",
    "unknown_field",
    "missing_database",
    "wrong_host",
    "wrong_port",
    "string_port",
    "bool_port",
    "wrong_database",
    "wrong_app",
    "wrong_env",
    "wrong_cloud",
    "wrong_region",
    "wrong_endpoint",
    "wrong_tenant",
    "missing_environment",
    "empty_entries",
    "missing_entry",
    "extra_entry",
    "duplicate_runtime",
    "duplicate_role",
    "duplicate_secret",
    "duplicate_candidate",
    "admin_role",
    "other_tenant_role",
    "foreign_secret",
    "secret_whitespace",
    "unknown_target_field",
    "missing_previous",
    "bad_previous",
    "bad_candidate",
    "zero_candidate",
    "same_version",
    "bad_phase",
    "missing_phase",
    "wrong_scope",
    "bad_operation",
    "incomplete_failure",
    "unknown_entry_field",
    "complete_wrong_host",
    "recovered_wrong_secret",
]


def corrupt(record: dict[str, Any], case: str) -> Any:
    row = record["entries"][0]
    if case == "root_list":
        return [record]
    if case == "root_null":
        return None
    if case in {"legacy_version", "float_version", "string_version", "bool_version"}:
        record["version"] = {
            "legacy_version": 1,
            "float_version": 2.0,
            "string_version": "2",
            "bool_version": True,
        }[case]
    elif case == "unknown_field":
        record["password"] = "private-input-do-not-log"
    elif case.startswith("missing_") and case in {
        "missing_database",
        "missing_environment",
        "missing_phase",
    }:
        del record[case.removeprefix("missing_")]
    elif case in {
        "wrong_host",
        "wrong_port",
        "string_port",
        "bool_port",
        "wrong_database",
        "complete_wrong_host",
    }:
        name, value = {
            "wrong_host": ("host", "attacker.example"),
            "wrong_port": ("port", 1234),
            "string_port": ("port", str(record["database"]["port"])),
            "bool_port": ("port", True),
            "wrong_database": ("name", "other_database"),
            "complete_wrong_host": ("host", "attacker.example"),
        }[case]
        record["database"][name] = value
        if case == "complete_wrong_host":
            record["phase"] = "complete"
    elif case in {
        "wrong_app",
        "wrong_env",
        "wrong_cloud",
        "wrong_region",
        "wrong_endpoint",
        "wrong_tenant",
    }:
        name, value = {
            "wrong_app": ("app_name", "other-project"),
            "wrong_env": ("app_env", "production"),
            "wrong_cloud": ("cloud_runtime", "aws"),
            "wrong_region": ("aws_region", "us-east-2"),
            "wrong_endpoint": ("aws_endpoint_url", "http://attacker.example:4566"),
            "wrong_tenant": ("tenant", "victim"),
        }[case]
        record["environment"][name] = value
    elif case == "empty_entries":
        record["entries"] = []
    elif case == "missing_entry":
        record["entries"].pop()
    elif case == "extra_entry":
        record["entries"].append(deepcopy(row))
    elif case.startswith("duplicate_"):
        name = case.removeprefix("duplicate_")
        if name == "candidate":
            record["entries"][1]["candidate_version"] = row["candidate_version"]
        else:
            key = "secret_id" if name == "secret" else name
            record["entries"][1]["target"][key] = row["target"][key]
    elif case in {
        "admin_role",
        "other_tenant_role",
        "foreign_secret",
        "secret_whitespace",
        "unknown_target_field",
        "recovered_wrong_secret",
    }:
        key, value = {
            "admin_role": ("role", "migration_owner"),
            "other_tenant_role": ("tenant", "victim"),
            "foreign_secret": ("secret_id", "/other-project/database/application"),
            "secret_whitespace": ("secret_id", row["target"]["secret_id"] + " "),
            "unknown_target_field": ("password", "private-input-do-not-log"),
            "recovered_wrong_secret": ("secret_id", "/other-project/database/application"),
        }[case]
        row["target"][key] = value
        if case == "recovered_wrong_secret":
            record["phase"] = "recovered"
    elif case == "missing_previous":
        del row["previous_version"]
    elif case == "bad_previous":
        row["previous_version"] = "not-a-version"
    elif case == "bad_candidate":
        row["candidate_version"] = "invalid"
    elif case == "zero_candidate":
        row["candidate_version"] = "0" * 32
    elif case == "same_version":
        row["previous_version"] = row["candidate_version"]
    elif case == "bad_phase":
        record["phase"] = "execute_any_sql"
    elif case == "wrong_scope":
        record["scope"] = "observability"
    elif case == "bad_operation":
        record["operation_id"] = "invalid"
    elif case == "incomplete_failure":
        del record["failure_type"]
    elif case == "unknown_entry_field":
        row["sql"] = "ALTER ROLE postgres PASSWORD 'unsafe'"
    else:
        raise AssertionError(case)
    return record


@pytest.mark.parametrize("case", STATIC_CASES)
async def test_invalid_journal_stops_before_connecting_and_preserves_all_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    path.write_text(json.dumps(corrupt(json.loads(path.read_text()), case)), encoding="utf-8")
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )
    connections: list[bool] = []

    @asynccontextmanager
    async def forbidden(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        connections.append(True)
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", forbidden)
    with pytest.raises(CredentialPreflightError) as error:
        await recover(settings, path, service)
    assert "private-input" not in str(error.value)
    assert not connections
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before
    assert not service.calls


@pytest.mark.parametrize(
    "data",
    [
        '{"version":2,"version":1}',
        '{"database":{"port":1,"port":2}}',
        '{"version":NaN}',
        '{"version":Infinity}',
        "{",
        '"private-input-do-not-log"',
        " " * 65537,
    ],
    ids=[
        "duplicate-root",
        "duplicate-nested",
        "nan",
        "infinity",
        "invalid-json",
        "wrong-root",
        "oversized",
    ],
)
async def test_malformed_duplicate_and_oversized_json_is_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: str,
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    path.write_text(data, encoding="utf-8")
    before = path.read_bytes()
    connections: list[bool] = []

    @asynccontextmanager
    async def forbidden(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        connections.append(True)
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", forbidden)
    with pytest.raises(CredentialPreflightError) as error:
        await recover(settings, path, service)
    assert "private-input" not in str(error.value)
    assert not connections
    assert path.read_bytes() == before and not service.calls


@pytest.mark.parametrize(
    "case",
    [
        "missing_secret",
        "unknown_candidate",
        "unbound_candidate",
        "foreign_payload",
        "wrong_endpoint_payload",
        "response_version",
    ],
)
async def test_live_version_checks_finish_before_password_or_label_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    settings, targets, service, database, path = await unfinished(tmp_path)
    target = targets[2]
    record = json.loads(path.read_text())
    row = record["entries"][2]
    if case == "missing_secret":
        del service.values[target.secret_id]
        del service.labels[target.secret_id]
    elif case == "unknown_candidate":
        row["candidate_version"] = uuid4().hex
        path.write_text(json.dumps(record), encoding="utf-8")
    elif case == "unbound_candidate":
        service.labels[target.secret_id][row["candidate_version"]].remove("AWSPENDING")
    elif case in {"foreign_payload", "wrong_endpoint_payload"}:
        value = json.loads(service.values[target.secret_id][row["previous_version"]])
        value["username" if case == "foreign_payload" else "host"] = "attacker"
        service.values[target.secret_id][row["previous_version"]] = json.dumps(value)
    else:
        original = service.get_secret_value

        def wrong_version(**kwargs: Any) -> dict[str, str]:
            value = original(**kwargs)
            value["VersionId"] = uuid4().hex
            return value

        monkeypatch.setattr(service, "get_secret_value", wrong_version)
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before
    assert not service.calls.get("put_secret_value") and not service.calls.get(
        "update_secret_version_stage"
    )
    assert not service.calls.get("create_secret")


async def test_repeated_and_concurrent_recovery_only_mutate_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    lock = asyncio.Lock()

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        async with lock:
            yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    writes = database.writes
    await asyncio.gather(recover(settings, path, service), recover(settings, path, service))
    assert database.writes == writes + 1
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )
    service.calls.clear()
    await recover(settings, path, service)
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before
    assert not service.calls


async def test_input_replacement_while_waiting_is_revalidated_under_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    writes = database.writes

    @asynccontextmanager
    async def replaced(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        path.write_text(json.dumps(corrupt(json.loads(path.read_text()), "admin_role")))
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", replaced)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert database.writes == writes and not service.calls
    assert json.loads(path.read_text())["entries"][0]["target"]["role"] == "migration_owner"


async def test_input_changed_during_cloud_preflight_is_not_overwritten_or_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, _, service, database, path = await unfinished(tmp_path)
    writes = database.writes
    before = deepcopy((service.values, service.labels, database.values))
    original = service.describe_secret
    changed: bytes | None = None

    def replacing(**kwargs: Any) -> dict[str, Any]:
        nonlocal changed
        if changed is None:
            path.write_text(json.dumps(corrupt(json.loads(path.read_text()), "foreign_secret")))
            changed = path.read_bytes()
        return original(**kwargs)

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr(service, "describe_secret", replacing)
    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    assert database.writes == writes and (service.values, service.labels, database.values) == before
    assert path.read_bytes() == changed


async def test_monitor_journal_cannot_select_its_own_recovery_scope(tmp_path: Path) -> None:
    settings = Settings.model_construct(credential_rotation_maintenance_mode=True)
    target = Target(
        "observability", "observability_reader", "/connected-vehicle/local/database/observability"
    )
    service, database = MemorySecrets(), Passwords()
    service.create_secret(Name=target.secret_id)
    path = await rotate(
        settings, [target], {target.role: "monitor-fixture"}, service, database, directory=tmp_path
    )
    writes = database.writes
    service.calls.clear()
    with pytest.raises(CredentialPreflightError):
        await recover(settings, path, service)
    await recover(settings, path, service, scope="observability")
    assert database.writes == writes and not service.calls


async def test_provisioning_checks_containers_before_role_or_schema_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, targets, service, _ = setup(True)
    del service.values[targets[2].secret_id]
    del service.labels[targets[2].secret_id]
    for role in DATABASE_USERS.values():
        monkeypatch.setenv(role.upper() + "_PASSWORD", "candidate-" + role)
    roles, grants = AsyncMock(), AsyncMock()
    with (
        patch("database.provision_runtime_credentials.AWSClientFactory") as factory,
        patch("database.provision_runtime_credentials.prepare_roles", roles),
        patch("database.provision_runtime_credentials.grant_runtimes", grants),
    ):
        factory.return_value.secrets_manager.return_value = service
        with pytest.raises(CredentialPreflightError, match="Terraform"):
            await provision(settings)
    roles.assert_not_awaited()
    grants.assert_not_awaited()
    assert not service.calls.get("create_secret")


async def test_forged_initial_recovery_cannot_clear_a_secretless_existing_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, targets, service, database = setup(False)
    settings.credential_rotation_maintenance_mode = True
    database.values[targets[2].role] = "legacy-password-with-no-secret"
    record = {
        "version": 2,
        "operation_id": uuid4().hex,
        "phase": "preparing",
        "scope": "runtimes",
        "database": database_target(settings),
        "environment": environment_target(settings),
        "entries": [
            {
                "target": {
                    "runtime": t.runtime,
                    "role": t.role,
                    "secret_id": t.secret_id,
                    "tenant": t.tenant,
                },
                "previous_version": None,
                "candidate_version": uuid4().hex,
            }
            for t in targets
        ],
    }
    path = tmp_path / "forged-initial.json"
    path.write_text(json.dumps(record))
    before = deepcopy(
        (service.values, service.labels, database.values, database.writes, path.read_bytes())
    )

    @asynccontextmanager
    async def manager(settings: Settings, targets: list[Target]) -> AsyncIterator[Passwords]:
        yield database

    monkeypatch.setattr("database.credential_rotation.password_manager", manager)
    with pytest.raises(CredentialPreflightError, match="existing database password"):
        await recover(settings, path, service)
    assert (
        service.values,
        service.labels,
        database.values,
        database.writes,
        path.read_bytes(),
    ) == before
