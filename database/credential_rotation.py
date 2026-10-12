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
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    DatabaseCredentials,
    bootstrap_database_settings,
    runtime_database_user,
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
        if self.runtime == "observability":
            valid = self.role == "observability_reader" and self.tenant is None
        else:
            valid = self.runtime in DATABASE_USERS and self.role == runtime_database_user(
                cast(Any, self.runtime), self.tenant
            )
        if not valid or not self.secret_id:
            raise ValueError("Invalid rotation target identity")


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
        credentials = DatabaseCredentials.model_validate(payload)
        if (
            credentials.username != target.role
            or credentials.tenant_id != target.tenant
            or credentials.host != self.settings.database_host
            or credentials.port != self.settings.database_port
            or credentials.dbname != self.settings.database_name
        ):
            raise ValueError("Rotation credential endpoint/identity mismatch")
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


async def current_version(client: Any, secret: str) -> str | None:
    try:
        metadata = await request(client, "describe_secret", SecretId=secret)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        await request(client, "create_secret", Name=secret)
        return None
    versions = [
        key
        for key, stages in metadata.get("VersionIdsToStages", {}).items()
        if "AWSCURRENT" in stages
    ]
    if len(versions) > 1:
        raise ValueError("Ambiguous current credential version")
    return versions[0] if versions else None


async def payload(client: Any, target: Target, version: str) -> dict[str, Any]:
    response = await request(
        client, "get_secret_value", SecretId=target.secret_id, VersionId=version
    )
    return cast(dict[str, Any], json.loads(response["SecretString"]))


async def restore(
    record: dict[str, Any],
    client: Any,
    backend: PasswordBackend,
    path: Path,
) -> None:
    targets = [Target(**row["target"]) for row in record["entries"]]
    old: dict[str, str | None] = {}
    for target, entry in zip(targets, record["entries"], strict=True):
        target.validate()
        current = await current_version(client, target.secret_id)
        if current not in {entry["previous_version"], entry["candidate_version"]}:
            raise ValueError("Rotation recovery was superseded by another operation")
        old[target.role] = (
            None
            if entry["previous_version"] is None
            else (await payload(client, target, entry["previous_version"]))["password"]
        )
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
    operation = uuid4().hex
    path = directory / f"{operation}.json"
    record: dict[str, Any] = {
        "version": 1,
        "operation_id": operation,
        "phase": "preparing",
        "database": {
            "host": settings.database_host,
            "port": settings.database_port,
            "name": settings.database_name,
        },
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
            await restore(record, client, backend, path)
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


async def recover(settings: Settings, path: Path, client: Any) -> None:
    if not settings.credential_rotation_maintenance_mode:
        raise ValueError("Credential recovery requires a maintenance window")
    record = json.loads(path.read_text())
    if record["version"] != 1 or record["database"] != {
        "host": settings.database_host,
        "port": settings.database_port,
        "name": settings.database_name,
    }:
        raise ValueError("Recovery journal database mismatch")
    if record["phase"] in {"complete", "recovered"}:
        return
    targets = [Target(**entry["target"]) for entry in record["entries"]]
    async with password_manager(settings, targets) as backend:
        await restore(record, client, backend, path)
