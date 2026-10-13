"""Recoverable single-user rotation; existing runtimes require a maintenance window."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from botocore.exceptions import ClientError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from database.bootstrap_cluster import SQLDriver, check_bootstrap
from database.credential_journal import (
    CredentialPreflightError,
    JournalTarget,
    RecoveryScope,
    database_target,
    environment_target,
    load_journal,
    strict_json,
    validate_journal,
    validate_targets,
)
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DatabaseCredentials,
    bootstrap_database_settings,
)
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.runtime_security import verify_runtime_database_security


@dataclass(frozen=True)
class Target:
    runtime: str
    role: str
    secret_id: str
    tenant: str | None = None

    def validate(self) -> None:
        try:
            JournalTarget.model_validate(asdict(self))
        except ValueError:
            raise CredentialPreflightError("Invalid rotation target identity") from None


class PasswordBackend(Protocol):
    async def has_password(self, role: str) -> bool: ...
    async def set_passwords(self, values: dict[str, str | None]) -> None: ...
    async def verify(self, target: Target, payload: dict[str, Any]) -> None: ...


class PostgreSQLPasswords:
    def __init__(self, settings: Settings, connection: AsyncConnection) -> None:
        self.settings, self.connection = settings, connection

    async def has_password(self, role: str) -> bool:
        result = bool(
            await self.connection.scalar(
                text("SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname=:role"),
                {"role": role},
            )
        )
        await self.connection.commit()
        return result

    async def set_passwords(self, values: dict[str, str | None]) -> None:
        async with self.connection.begin():
            await check_bootstrap(self.connection, self.settings)
            driver = cast(SQLDriver, (await self.connection.get_raw_connection()).driver_connection)
            for role, password in values.items():
                name = await self.connection.scalar(
                    text("SELECT quote_ident(:role)"), {"role": role}
                )
                value = (
                    "NULL"
                    if password is None
                    else await self.connection.scalar(
                        text("SELECT quote_literal(:password)"), {"password": password}
                    )
                )
                await driver.execute(f"ALTER ROLE {name} PASSWORD {value}")

    async def verify(self, target: Target, payload: dict[str, Any]) -> None:
        credentials = validate_payload(self.settings, target, payload)
        engine = create_database_engine(
            self.settings.model_copy(
                update={
                    "database_username": target.role,
                    "database_password": credentials.password,
                }
            )
        )
        try:
            async with engine.connect() as connection:
                identity = (
                    await connection.execute(text("SELECT session_user,current_user"))
                ).one()
                if tuple(identity) != (target.role, target.role):
                    raise ValueError("Rotation login identity mismatch")
                if target.runtime == "observability":
                    await connection.execute(text("SELECT public.runtime_health_summary()"))
            if target.runtime != "observability":
                await verify_runtime_database_security(
                    engine, cast(Any, target.runtime), tenant_id=target.tenant
                )
        finally:
            await engine.dispose()


@asynccontextmanager
async def password_manager(
    settings: Settings, targets: list[Target]
) -> AsyncIterator[PasswordBackend]:
    for target in targets:
        target.validate()
    # Serialize overlapping role sets as well as identical sets in this database.
    # A deployment must use one management database for cluster-global roles.
    key = 0x435643524544454E
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.connect() as connection:
            await check_bootstrap(connection, settings)
            await connection.execute(text("SET lock_timeout='5s'"))
            await connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": key})
            await connection.commit()
            try:
                yield PostgreSQLPasswords(settings, connection)
            finally:
                await connection.rollback()
                await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
                await connection.commit()
    finally:
        await engine.dispose()


def save_journal(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


async def request(client: Any, method: str, **kwargs: Any) -> Any:
    return await asyncio.to_thread(getattr(client, method), **kwargs)


async def secret_metadata(client: Any, secret: str) -> dict[str, list[str]]:
    try:
        metadata = await request(client, "describe_secret", SecretId=secret)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        raise CredentialPreflightError(
            "Secret does not exist; pre-create it with Terraform"
        ) from None
    versions = metadata.get("VersionIdsToStages", {})
    if not isinstance(versions, dict) or any(
        not isinstance(key, str)
        or not isinstance(stages, list)
        or any(not isinstance(stage, str) for stage in stages)
        for key, stages in versions.items()
    ):
        raise CredentialPreflightError("Invalid Secret version metadata")
    return cast(dict[str, list[str]], versions)


async def current_version(client: Any, secret: str) -> str | None:
    metadata = await secret_metadata(client, secret)
    versions = [key for key, stages in metadata.items() if "AWSCURRENT" in stages]
    if len(versions) > 1:
        raise CredentialPreflightError("Ambiguous current credential version")
    return versions[0] if versions else None


async def payload(client: Any, target: Target, version: str) -> dict[str, Any]:
    response = await request(
        client, "get_secret_value", SecretId=target.secret_id, VersionId=version
    )
    if response.get("VersionId") != version:
        raise CredentialPreflightError("Secret response version mismatch")
    try:
        return cast(dict[str, Any], strict_json(response["SecretString"]))
    except (ValueError, KeyError, TypeError):
        raise CredentialPreflightError("Invalid credential version payload") from None


def validate_payload(
    settings: Settings, target: Target, value: dict[str, Any]
) -> DatabaseCredentials:
    try:
        credentials = DatabaseCredentials.model_validate(value, strict=True)
        if (
            credentials.username != target.role
            or credentials.tenant_id != target.tenant
            or credentials.host != settings.database_host
            or credentials.port != settings.database_port
            or credentials.dbname != settings.database_name
        ):
            raise ValueError("Credential identity mismatch")
        return credentials
    except ValueError:
        raise CredentialPreflightError("Rotation credential endpoint/identity mismatch") from None


async def recovery_passwords(
    record: dict[str, Any],
    client: Any,
    backend: PasswordBackend,
    *,
    settings: Settings,
    scope: RecoveryScope = "runtimes",
) -> dict[str, str | None]:
    validate_journal(record, settings, scope)
    targets = [Target(**row["target"]) for row in record["entries"]]
    old: dict[str, str | None] = {}
    for target, entry in zip(targets, record["entries"], strict=True):
        target.validate()
        metadata = await secret_metadata(client, target.secret_id)
        currents = [key for key, labels in metadata.items() if "AWSCURRENT" in labels]
        if len(currents) > 1:
            raise CredentialPreflightError("Ambiguous current credential version")
        current = currents[0] if currents else None
        if current not in {entry["previous_version"], entry["candidate_version"]}:
            raise CredentialPreflightError("Rotation recovery was superseded by another operation")
        candidate = entry["candidate_version"]
        if candidate in metadata:
            if "AWSPENDING" not in metadata[candidate]:
                raise CredentialPreflightError(
                    "Candidate version is not bound to the pending operation"
                )
            validate_payload(settings, target, await payload(client, target, candidate))
        else:
            preparing = "preparing" in {
                record["phase"],
                record.get("failed_phase"),
                record.get("recovery_from_phase"),
            }
            later_pending = any(
                "AWSPENDING" in labels
                and key != entry["previous_version"]
                and not (
                    current is None
                    and entry["previous_version"] is None
                    and "AWSPREVIOUS" in labels
                )
                for key, labels in metadata.items()
            )
            if not preparing or later_pending:
                raise CredentialPreflightError(
                    "Candidate credential version is missing or superseded"
                )
        previous = entry["previous_version"]
        if previous is not None:
            required = "AWSCURRENT" if current == previous else "AWSPREVIOUS"
            if required not in metadata.get(previous, []):
                raise CredentialPreflightError(
                    "Previous version is not bound to the current operation"
                )
            old[target.role] = validate_payload(
                settings, target, await payload(client, target, previous)
            ).password.get_secret_value()
        else:
            if candidate not in metadata and await backend.has_password(target.role):
                raise CredentialPreflightError(
                    "Unwritten initial candidate cannot recover an existing database password"
                )
            old[target.role] = None
    return old


async def restore(
    record: dict[str, Any],
    client: Any,
    backend: PasswordBackend,
    path: Path,
    *,
    settings: Settings,
    scope: RecoveryScope = "runtimes",
    check_source: bool = False,
) -> None:
    try:
        old = await recovery_passwords(record, client, backend, settings=settings, scope=scope)
    except CredentialPreflightError:
        raise
    except Exception:
        raise CredentialPreflightError("Recovery versions could not be verified") from None
    if check_source and load_journal(path, settings, scope) != record:
        raise CredentialPreflightError("Recovery journal changed during preflight")
    targets = [Target(**row["target"]) for row in record["entries"]]
    record.setdefault("recovery_from_phase", record.get("failed_phase") or record["phase"])
    record["phase"] = "recovering"
    save_journal(path, record)
    await backend.set_passwords(old)
    for target, entry in zip(targets, record["entries"], strict=True):
        current = await current_version(client, target.secret_id)
        previous = entry["previous_version"]
        if current != previous:
            args: dict[str, Any] = {"SecretId": target.secret_id, "VersionStage": "AWSCURRENT"}
            if previous is not None:
                args["MoveToVersionId"] = previous
            if current is not None:
                args["RemoveFromVersionId"] = current
            await request(client, "update_secret_version_stage", **args)
        if await current_version(client, target.secret_id) != previous:
            raise ValueError("Recovery current-version verification failed")
        if previous is not None:
            await backend.verify(target, await payload(client, target, previous))
        elif await backend.has_password(target.role):
            raise ValueError("Initial credential password recovery failed")
    record["phase"] = "recovered"
    save_journal(path, record)


async def rotate(
    settings: Settings,
    targets: list[Target],
    passwords: dict[str, str],
    client: Any,
    backend: PasswordBackend,
    *,
    directory: Path = Path(".runtime-reports/credential-operations"),
) -> Path:
    if (
        not targets
        or len({t.role for t in targets}) != len(targets)
        or len({t.secret_id for t in targets}) != len(targets)
    ):
        raise ValueError("Rotation targets must be distinct")
    if any(not passwords.get(t.role) for t in targets) or len(set(passwords.values())) != len(
        targets
    ):
        raise ValueError("Rotation requires distinct nonempty candidate passwords")
    for target in targets:
        target.validate()
    scope: RecoveryScope = "observability" if targets[0].runtime == "observability" else "runtimes"
    validate_targets(settings, [asdict(target) for target in targets], scope)
    operation = uuid4().hex
    path = directory / f"{operation}.json"
    record: dict[str, Any] = {
        "version": 2,
        "operation_id": operation,
        "phase": "preparing",
        "scope": scope,
        "database": database_target(settings),
        "environment": environment_target(settings),
        "entries": [],
    }
    # Preflight all active credentials before changing any password or current label.
    for target in targets:
        previous = await current_version(client, target.secret_id)
        if previous is not None:
            if not settings.credential_rotation_maintenance_mode:
                raise ValueError("Existing credential rotation requires a maintenance window")
            await backend.verify(target, await payload(client, target, previous))
        elif await backend.has_password(target.role):
            raise ValueError("Existing database password has no recoverable current Secret")
        record["entries"].append(
            {
                "target": asdict(target),
                "previous_version": previous,
                "candidate_version": uuid4().hex,
            }
        )
    validate_journal(record, settings, scope)
    save_journal(path, record)
    try:
        for target, entry in zip(targets, record["entries"], strict=True):
            candidate = dict(
                engine="postgres",
                host=settings.database_host,
                port=settings.database_port,
                dbname=settings.database_name,
                username=target.role,
                password=passwords[target.role],
            )
            if target.tenant is not None:
                candidate["tenant_id"] = target.tenant
            await request(
                client,
                "put_secret_value",
                SecretId=target.secret_id,
                ClientRequestToken=entry["candidate_version"],
                SecretString=json.dumps(candidate),
                VersionStages=(
                    ["AWSPENDING", "AWSCURRENT"]
                    if entry["previous_version"] is None
                    else ["AWSPENDING"]
                ),
            )
        record["phase"] = "prepared"
        save_journal(path, record)
        await backend.set_passwords({t.role: passwords[t.role] for t in targets})
        record["phase"] = "database_changed"
        save_journal(path, record)
        for target, entry in zip(targets, record["entries"], strict=True):
            await backend.verify(target, await payload(client, target, entry["candidate_version"]))
        record["phase"] = "verified"
        save_journal(path, record)
        for target, entry in zip(targets, record["entries"], strict=True):
            # The first version receives AWSCURRENT automatically on AWS. New
            # runtimes must stay stopped until the whole operation completes.
            current = await current_version(client, target.secret_id)
            if current == entry["candidate_version"]:
                continue
            if current != entry["previous_version"]:
                raise ValueError("Concurrent credential publication detected")
            args = {
                "SecretId": target.secret_id,
                "VersionStage": "AWSCURRENT",
                "MoveToVersionId": entry["candidate_version"],
            }
            if entry["previous_version"] is not None:
                args["RemoveFromVersionId"] = entry["previous_version"]
            await request(client, "update_secret_version_stage", **args)
        for target, entry in zip(targets, record["entries"], strict=True):
            if await current_version(client, target.secret_id) != entry["candidate_version"]:
                raise ValueError("Current credential publication mismatch")
        record["phase"] = "complete"
        save_journal(path, record)
        return path
    except Exception as error:
        record["failure_type"] = type(error).__name__
        record["failed_phase"] = record["phase"]
        if isinstance(error, ClientError):
            record["service_error_code"] = error.response["Error"]["Code"]
        try:
            await restore(record, client, backend, path, settings=settings, scope=scope)
        except Exception:
            record["phase"] = "recovery_required"
            save_journal(path, record)
            raise RuntimeError(
                f"Credential recovery required ({record['failure_type']}, "
                f"{record['failed_phase']}); journal: {path}"
            ) from None
        raise RuntimeError(
            f"Credential rotation failed and was recovered ({record['failure_type']}, "
            f"{record['failed_phase']}); journal: {path}"
        ) from None


async def recover(
    settings: Settings,
    path: Path,
    client: Any,
    *,
    scope: RecoveryScope = "runtimes",
) -> None:
    if not settings.credential_rotation_maintenance_mode:
        raise ValueError("Credential recovery requires a maintenance window")
    record = load_journal(path, settings, scope)
    if record["phase"] in {"complete", "recovered"}:
        return
    targets = [Target(**entry["target"]) for entry in record["entries"]]
    try:
        async with password_manager(settings, targets) as backend:
            # Re-read under the database lock: a concurrent recovery may have
            # finished, or the input may have been replaced while this caller waited.
            record = load_journal(path, settings, scope)
            if record["phase"] in {"complete", "recovered"}:
                return
            await restore(
                record,
                client,
                backend,
                path,
                settings=settings,
                scope=scope,
                check_source=True,
            )
    except CredentialPreflightError:
        raise
    except Exception:
        record["phase"] = "recovery_required"
        save_journal(path, record)
        # SQLAlchemy errors can include bound passwords. Keep the terminal error
        # as sanitized as the durable journal, including when recovery itself fails.
        raise RuntimeError(f"Credential recovery required; journal: {path}") from None
