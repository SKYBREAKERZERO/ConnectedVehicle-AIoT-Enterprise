"""Recoverable single-user rotation; existing runtimes require a maintenance window."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from botocore.exceptions import ClientError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from database.bootstrap_cluster import SQLDriver, check_bootstrap
from database.credential_audit import save_checkpoint
from database.credential_journal import (
    CredentialPreflightError,
    JournalTarget,
    Phase,
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

save_journal = save_checkpoint


def transition(path: Path, record: dict[str, Any], phase: Phase) -> None:
    """Do not advance the in-memory phase until its durable checkpoint succeeds."""
    candidate = deepcopy(record)
    candidate["phase"] = phase
    save_journal(path, candidate)
    record.clear()
    record.update(candidate)


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

                async def unlock() -> None:
                    await connection.rollback()
                    await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
                    await connection.commit()

                await settled(asyncio.create_task(unlock()))
    finally:
        await settled(asyncio.create_task(engine.dispose()))


async def request(client: Any, method: str, **kwargs: Any) -> Any:
    task = asyncio.create_task(asyncio.to_thread(getattr(client, method), **kwargs))
    return await settled(task)


async def settled(task: asyncio.Task[Any]) -> Any:
    # A cancelled thread keeps running. Hold the caller's management lock until
    # its AWS request actually settles, even if cancellation is requested again.
    cancelled = False
    while True:
        try:
            value = await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
            if task.cancelled():
                raise
        except Exception:
            if cancelled:
                raise asyncio.CancelledError from None
            raise
        else:
            if cancelled:
                raise asyncio.CancelledError
            return value


async def secret_metadata(client: Any, secret: str) -> dict[str, list[str]]:
    try:
        metadata = await request(client, "describe_secret", SecretId=secret)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        raise CredentialPreflightError(
            "Secret does not exist; pre-create it with Terraform"
        ) from None
    if metadata.get("DeletedDate") is not None:
        raise CredentialPreflightError("Secret is scheduled for deletion")
    identity = metadata.get("ARN") if secret.startswith("arn:") else metadata.get("Name")
    if identity != secret:
        raise CredentialPreflightError("Secret resource identity mismatch")
    versions = metadata.get("VersionIdsToStages", {})
    if not isinstance(versions, dict) or any(
        not isinstance(key, str)
        or not isinstance(stages, list)
        or not 32 <= len(key) <= 64
        or not key.isascii()
        or any(not (char.isalnum() or char == "-") for char in key)
        or any(not isinstance(stage, str) or not stage for stage in stages)
        or len(stages) != len(set(stages))
        for key, stages in versions.items()
    ):
        raise CredentialPreflightError("Invalid Secret version metadata")
    for stage in ("AWSCURRENT", "AWSPENDING", "AWSPREVIOUS"):
        if sum(stage in labels for labels in versions.values()) > 1:
            raise CredentialPreflightError("Ambiguous Secret staging label")
    return cast(dict[str, list[str]], versions)


async def current_version(client: Any, secret: str) -> str | None:
    metadata = await secret_metadata(client, secret)
    versions = [key for key, stages in metadata.items() if "AWSCURRENT" in stages]
    if len(versions) > 1:
        raise CredentialPreflightError("Ambiguous current credential version")
    return versions[0] if versions else None


async def ready_version(client: Any, secret: str) -> str | None:
    metadata = await secret_metadata(client, secret)
    if any("AWSPENDING" in labels for labels in metadata.values()):
        raise CredentialPreflightError(
            "Pending operation requires recovery or explicit terminal retirement"
        )
    currents = [key for key, labels in metadata.items() if "AWSCURRENT" in labels]
    return currents[0] if currents else None


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
    metadata_by_secret = {
        target.secret_id: await secret_metadata(client, target.secret_id) for target in targets
    }
    old: dict[str, str | None] = {}
    for target, entry in zip(targets, record["entries"], strict=True):
        target.validate()
        metadata = metadata_by_secret[target.secret_id]
        currents = [key for key, labels in metadata.items() if "AWSCURRENT" in labels]
        if len(currents) > 1:
            raise CredentialPreflightError("Ambiguous current credential version")
        current = currents[0] if currents else None
        if current not in {entry["previous_version"], entry["candidate_version"]}:
            raise CredentialPreflightError("Rotation recovery was superseded by another operation")
        candidate = entry["candidate_version"]
        if any("AWSPENDING" in labels and key != candidate for key, labels in metadata.items()):
            raise CredentialPreflightError("Pending version belongs to another operation")
        if candidate in metadata:
            retiring = record["phase"] == "recovery_verified" or (
                record["phase"] == "recovery_required"
                and record.get("failed_phase") == "recovery_verified"
            )
            if "AWSPENDING" not in metadata[candidate] and not retiring:
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
            retiring = record["phase"] == "recovery_verified" or (
                record["phase"] == "recovery_required"
                and record.get("failed_phase") == "recovery_verified"
            )
            if (not preparing and not retiring) or later_pending:
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
    retirement_resume = record["phase"] == "recovery_verified" or (
        record["phase"] == "recovery_required" and record.get("failed_phase") == "recovery_verified"
    )
    if retirement_resume:
        for target, entry in zip(targets, record["entries"], strict=True):
            if await current_version(client, target.secret_id) != entry["previous_version"]:
                raise CredentialPreflightError("Verified recovery was superseded")
            if entry["previous_version"] is not None:
                await backend.verify(
                    target, await payload(client, target, entry["previous_version"])
                )
            elif await backend.has_password(target.role):
                raise CredentialPreflightError("Verified initial recovery password mismatch")
        if check_source and load_journal(path, settings, scope) != record:
            raise CredentialPreflightError("Recovery journal changed during verification")
        record.setdefault("recovery_from_phase", record.get("failed_phase") or record["phase"])
        transition(path, record, "recovery_verified")
        await retire_pending(record, client)
        await verify_terminal_credentials(record, client, backend, settings, forward=False)
        transition(path, record, "recovered")
        return
    record.setdefault("recovery_from_phase", record.get("failed_phase") or record["phase"])
    transition(path, record, "recovering")
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
    transition(path, record, "recovery_verified")
    await retire_pending(record, client)
    await verify_terminal_credentials(record, client, backend, settings, forward=False)
    transition(path, record, "recovered")


async def retire_pending(record: dict[str, Any], client: Any) -> None:
    """Remove only this operation's Pending label; never delete a version or resource."""
    for entry in record["entries"]:
        secret = entry["target"]["secret_id"]
        metadata = await secret_metadata(client, secret)
        candidate = entry["candidate_version"]
        expected = (
            candidate if record["phase"] in {"retiring", "complete"} else entry["previous_version"]
        )
        if await current_version(client, secret) != expected:
            raise CredentialPreflightError("Current changed during retirement")
        if any("AWSPENDING" in labels and key != candidate for key, labels in metadata.items()):
            raise CredentialPreflightError("Pending version belongs to another operation")
    for entry in record["entries"]:
        secret, candidate = entry["target"]["secret_id"], entry["candidate_version"]
        metadata = await secret_metadata(client, secret)
        if any("AWSPENDING" in labels and key != candidate for key, labels in metadata.items()):
            raise CredentialPreflightError("Pending version belongs to another operation")
        expected = (
            candidate if record["phase"] in {"retiring", "complete"} else entry["previous_version"]
        )
        if await current_version(client, secret) != expected:
            raise CredentialPreflightError("Current changed during retirement")
        if "AWSPENDING" in metadata.get(candidate, []):
            await request(
                client,
                "update_secret_version_stage",
                SecretId=secret,
                VersionStage="AWSPENDING",
                RemoveFromVersionId=candidate,
            )
        if "AWSPENDING" in (await secret_metadata(client, secret)).get(candidate, []):
            raise RuntimeError("Pending retirement verification failed")

    for entry in record["entries"]:
        secret = entry["target"]["secret_id"]
        metadata = await secret_metadata(client, secret)
        expected = (
            entry["candidate_version"]
            if record["phase"] in {"retiring", "complete"}
            else entry["previous_version"]
        )
        if await current_version(client, secret) != expected or any(
            "AWSPENDING" in labels for labels in metadata.values()
        ):
            raise CredentialPreflightError("Retirement final reconciliation failed")


async def verify_terminal_credentials(
    record: dict[str, Any],
    client: Any,
    backend: PasswordBackend,
    settings: Settings,
    *,
    forward: bool,
) -> None:
    for entry in record["entries"]:
        target = Target(**entry["target"])
        expected = entry["candidate_version"] if forward else entry["previous_version"]
        if await current_version(client, target.secret_id) != expected:
            raise CredentialPreflightError("Terminal credential version changed")
        if expected is None:
            if await backend.has_password(target.role):
                raise ValueError("Terminal initial password recovery mismatch")
        else:
            value = await payload(client, target, expected)
            validate_payload(settings, target, value)
            await backend.verify(target, value)


async def finish_publication(
    record: dict[str, Any],
    client: Any,
    backend: PasswordBackend,
    path: Path,
    settings: Settings,
    scope: RecoveryScope,
    *,
    check_source: bool = False,
) -> None:
    validate_journal(record, settings, scope)
    for entry in record["entries"]:
        target = Target(**entry["target"])
        if await current_version(client, target.secret_id) != entry["candidate_version"]:
            raise CredentialPreflightError("Completed publication was superseded")
        value = await payload(client, target, entry["candidate_version"])
        validate_payload(settings, target, value)
        await backend.verify(target, value)
        metadata = await secret_metadata(client, target.secret_id)
        if any(
            "AWSPENDING" in labels and key != entry["candidate_version"]
            for key, labels in metadata.items()
        ):
            raise CredentialPreflightError("Pending version belongs to another operation")
    if check_source and load_journal(path, settings, scope) != record:
        raise CredentialPreflightError("Recovery journal changed during preflight")
    transition(path, record, "retiring")
    await retire_pending(record, client)
    await verify_terminal_credentials(record, client, backend, settings, forward=True)
    transition(path, record, "complete")


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
        "events": [],
    }
    # Preflight all active credentials before changing any password or current label.
    for target in targets:
        previous = await ready_version(client, target.secret_id)
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
            metadata = await secret_metadata(client, target.secret_id)
            if any("AWSPENDING" in labels for labels in metadata.values()):
                raise CredentialPreflightError("Concurrent Pending publication detected")
            if await current_version(client, target.secret_id) != entry["previous_version"]:
                raise CredentialPreflightError("Concurrent Current publication detected")
            response = await request(
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
            if response.get("VersionId") != entry["candidate_version"]:
                raise ValueError("Candidate publication response mismatch")
        transition(path, record, "prepared")
        for target, entry in zip(targets, record["entries"], strict=True):
            metadata = await secret_metadata(client, target.secret_id)
            candidate = entry["candidate_version"]
            if "AWSPENDING" not in metadata.get(candidate, []) or any(
                "AWSPENDING" in labels and key != candidate for key, labels in metadata.items()
            ):
                raise ValueError("Candidate Pending ownership changed before database mutation")
            expected = entry["previous_version"] or candidate
            if await current_version(client, target.secret_id) != expected:
                raise ValueError("Current changed before database mutation")
            validate_payload(settings, target, await payload(client, target, candidate))
        await backend.set_passwords({t.role: passwords[t.role] for t in targets})
        transition(path, record, "database_changed")
        for target, entry in zip(targets, record["entries"], strict=True):
            await backend.verify(target, await payload(client, target, entry["candidate_version"]))
        transition(path, record, "verified")
        transition(path, record, "promoting")
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
        await finish_publication(record, client, backend, path, settings, scope)
        return path
    except Exception as error:
        record["failure_type"] = type(error).__name__
        record["failed_phase"] = record["phase"]
        if isinstance(error, ClientError):
            record["service_error_code"] = error.response["Error"]["Code"]
        try:
            if record["failed_phase"] == "retiring":
                raise RuntimeError("Published credentials require retirement retry")
            await restore(record, client, backend, path, settings=settings, scope=scope)
        except Exception as recovery_error:
            if record["failed_phase"] != "retiring":
                record["recovery_failure_type"] = type(recovery_error).__name__
            if record["phase"] == "recovery_verified":
                record["failed_phase"] = "recovery_verified"
            transition(path, record, "recovery_required")
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
        if record.get("pending_retirement") in {"in_progress", "retry_required"}:
            raise CredentialPreflightError("Terminal Pending retirement requires --retire")
        return
    targets = [Target(**entry["target"]) for entry in record["entries"]]
    try:
        async with password_manager(settings, targets) as backend:
            record = load_journal(path, settings, scope)
            if record["phase"] in {"complete", "recovered"}:
                if record.get("pending_retirement") in {"in_progress", "retry_required"}:
                    raise CredentialPreflightError("Terminal Pending retirement requires --retire")
                return
            try:
                if record["phase"] == "retiring" or record.get("failed_phase") == "retiring":
                    await finish_publication(
                        record, client, backend, path, settings, scope, check_source=True
                    )
                    return
                await restore(
                    record, client, backend, path, settings=settings, scope=scope, check_source=True
                )
            except CredentialPreflightError:
                raise
            except Exception as error:
                if record["phase"] != "recovery_required":
                    record["failed_phase"] = record["phase"]
                if record.get("failure_type") is None:
                    record["failure_type"] = type(error).__name__
                record["recovery_failure_type"] = type(error).__name__
                transition(path, record, "recovery_required")
                raise RuntimeError(f"Credential recovery required; journal: {path}") from None
    except CredentialPreflightError:
        raise
    except Exception:
        raise RuntimeError(
            f"Credential recovery required or unavailable; journal: {path}"
        ) from None


async def retire(
    settings: Settings,
    path: Path,
    client: Any,
    *,
    scope: RecoveryScope = "runtimes",
) -> None:
    """Explicitly retire owned Pending on a legacy terminal operation; never change passwords."""
    if not settings.credential_rotation_maintenance_mode:
        raise ValueError("Credential retirement requires a maintenance window")
    record = load_journal(path, settings, scope)
    if record["phase"] not in {"complete", "recovered"}:
        raise CredentialPreflightError("Unfinished operation requires recovery before retirement")
    targets = [Target(**entry["target"]) for entry in record["entries"]]
    try:
        async with password_manager(settings, targets) as backend:
            record = load_journal(path, settings, scope)
            if record["phase"] not in {"complete", "recovered"}:
                raise CredentialPreflightError("Retirement journal changed while waiting")
            pending = False
            for target, entry in zip(targets, record["entries"], strict=True):
                metadata = await secret_metadata(client, target.secret_id)
                expected = (
                    entry["candidate_version"]
                    if record["phase"] == "complete"
                    else entry["previous_version"]
                )
                if await current_version(client, target.secret_id) != expected:
                    raise CredentialPreflightError("Terminal credential operation was superseded")
                if any(
                    "AWSPENDING" in labels and key != entry["candidate_version"]
                    for key, labels in metadata.items()
                ):
                    raise CredentialPreflightError("Pending version belongs to another operation")
                if expected is not None:
                    value = await payload(client, target, expected)
                    validate_payload(settings, target, value)
                    await backend.verify(target, value)
                elif await backend.has_password(target.role):
                    raise CredentialPreflightError("Terminal initial recovery password mismatch")
                if "AWSPENDING" in metadata.get(entry["candidate_version"], []):
                    validate_payload(
                        settings, target, await payload(client, target, entry["candidate_version"])
                    )
                    pending = True
            if load_journal(path, settings, scope) != record:
                raise CredentialPreflightError("Retirement journal changed during verification")
            if not pending and record.get("pending_retirement") in {None, "complete"}:
                return
            record.setdefault("events", [])
            record["pending_retirement"] = "in_progress"
            save_journal(path, record, action="retire_pending")
            try:
                await retire_pending(record, client)
                await verify_terminal_credentials(
                    record, client, backend, settings, forward=record["phase"] == "complete"
                )
                record["pending_retirement"] = "complete"
                save_journal(path, record, action="retire_pending")
            except Exception as error:
                record["pending_retirement"] = "retry_required"
                save_journal(
                    path, record, action="retire_pending", failure_type=type(error).__name__
                )
                raise RuntimeError(
                    f"Credential retirement retry required; journal: {path}"
                ) from None
    except CredentialPreflightError:
        raise
    except Exception:
        raise RuntimeError(
            f"Credential retirement unavailable or retry required; journal: {path}"
        ) from None
