"""Strict, configuration-bound recovery records. Journals never grant authority."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    runtime_database_user,
)

RecoveryScope = Literal["runtimes", "observability"]
Phase = Literal[
    "preparing",
    "prepared",
    "database_changed",
    "verified",
    "promoting",
    "retiring",
    "recovery_verified",
    "recovering",
    "recovery_required",
    "complete",
    "recovered",
]
MAX_JOURNAL_BYTES = 65536

TRANSITIONS: dict[str, set[str]] = {
    "preparing": {"prepared", "recovering", "recovery_required"},
    "prepared": {"database_changed", "recovering", "recovery_required"},
    "database_changed": {"verified", "recovering", "recovery_required"},
    "verified": {"promoting", "recovering", "recovery_required"},
    "promoting": {"retiring", "recovering", "recovery_required"},
    "retiring": {"complete", "recovery_required"},
    "recovering": {"recovery_verified", "recovery_required"},
    "recovery_verified": {"recovered", "recovery_required"},
    "recovery_required": {"recovering", "retiring", "recovery_verified"},
    "complete": set(),
    "recovered": set(),
}


class CredentialPreflightError(ValueError):
    """Rejected before password, Secret label or recovery journal mutation."""


class StrictRecord(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)


class JournalTarget(StrictRecord):
    runtime: Literal["application", "outbox", "remote-command", "observability"]
    role: str = Field(min_length=1, max_length=63)
    secret_id: str = Field(min_length=1, max_length=2048)
    tenant: str | None = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def identity(self) -> JournalTarget:
        if self.secret_id != self.secret_id.strip() or any(ord(c) < 32 for c in self.secret_id):
            raise ValueError("Invalid Secret identity")
        expected = (
            "observability_reader"
            if self.runtime == "observability"
            else runtime_database_user(self.runtime, self.tenant)
        )
        if self.role != expected or (self.runtime == "observability" and self.tenant is not None):
            raise ValueError("Invalid runtime identity")
        return self


class DatabaseTarget(StrictRecord):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    name: str = Field(min_length=1, max_length=63)


class EnvironmentTarget(StrictRecord):
    app_name: str = Field(min_length=1)
    app_env: Literal["local", "test", "aws-dev", "staging", "production"]
    cloud_runtime: Literal["localstack", "aws"]
    aws_region: str = Field(min_length=1)
    aws_endpoint_url: str | None
    tenant: str | None


class JournalEntry(StrictRecord):
    target: JournalTarget
    previous_version: str | None = Field(pattern=r"^[A-Za-z0-9-]{32,64}$")
    candidate_version: str = Field(pattern=r"^[0-9a-f]{32}$")

    @field_validator("candidate_version")
    @classmethod
    def candidate_uuid(cls, value: str) -> str:
        if UUID(value).version != 4:
            raise ValueError("Candidate must be a generated UUID4 version")
        return value

    @model_validator(mode="after")
    def separate_versions(self) -> JournalEntry:
        if self.previous_version == self.candidate_version:
            raise ValueError("Candidate and previous versions must differ")
        return self


class LifecycleEvent(StrictRecord):
    sequence: int = Field(ge=1)
    time: str = Field(min_length=1, max_length=64)
    phase: Phase
    action: Literal["state", "retire_pending"] = "state"
    retirement_status: Literal["in_progress", "complete", "retry_required"] | None = None

    @field_validator("time")
    @classmethod
    def timestamp(cls, value: str) -> str:
        if datetime.fromisoformat(value).utcoffset() is None:
            raise ValueError("Audit timestamp requires a timezone")
        return value

    failure_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


class Journal(StrictRecord):
    version: Literal[2]
    operation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    phase: Phase
    scope: RecoveryScope
    database: DatabaseTarget
    environment: EnvironmentTarget
    entries: list[JournalEntry] = Field(min_length=1, max_length=3)
    events: list[LifecycleEvent] = Field(default_factory=list)
    audit_offset: int = Field(default=0, ge=0)
    audit_archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    pending_retirement: Literal["in_progress", "complete", "retry_required"] | None = None
    failure_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    recovery_failure_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    failed_phase: Phase | None = None
    recovery_from_phase: Phase | None = None
    service_error_code: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

    @field_validator("operation_id")
    @classmethod
    def operation_uuid(cls, value: str) -> str:
        if UUID(value).version != 4:
            raise ValueError("Operation must be a generated UUID4 identity")
        return value

    @field_validator("version", mode="before")
    @classmethod
    def exact_version(cls, value: Any) -> Any:
        if type(value) is not int or value != 2:
            raise ValueError("Recovery requires journal version 2")
        return value

    @model_validator(mode="after")
    def unique_entries(self) -> Journal:
        for values in (
            [row.target.runtime for row in self.entries],
            [row.target.role for row in self.entries],
            [row.target.secret_id for row in self.entries],
            [row.candidate_version for row in self.entries],
        ):
            if len(set(values)) != len(values):
                raise ValueError("Duplicate recovery entries or candidate versions")
        if (self.audit_offset == 0) != (self.audit_archive_sha256 is None):
            raise ValueError("Invalid archive checkpoint")
        if self.pending_retirement is not None and self.phase not in {"complete", "recovered"}:
            raise ValueError("Explicit retirement requires a terminal operation")
        if self.audit_offset and not self.events:
            raise ValueError("Archive checkpoint requires a current audit event")
        validate_event_chain(self.events, self.audit_offset)
        if any(
            event.sequence != index
            for index, event in enumerate(self.events, self.audit_offset + 1)
        ):
            raise ValueError("Invalid audit sequence")
        if self.events and self.events[-1].phase != self.phase:
            raise ValueError("Audit phase mismatch")
        if self.phase == "recovery_required" and self.failure_type is None:
            raise ValueError("Recovery required must record a failure")
        if self.failed_phase in {"complete", "recovered", "recovery_required"}:
            raise ValueError("Invalid failed operation phase")
        if (
            self.pending_retirement is not None
            and self.events
            and (
                self.events[-1].action != "retire_pending"
                or self.events[-1].retirement_status != self.pending_retirement
            )
        ):
            raise ValueError("Retirement audit status mismatch")
        if (self.failure_type is None) != (self.failed_phase is None):
            raise ValueError("Incomplete failure metadata")
        if self.recovery_failure_type is not None and self.failure_type is None:
            raise ValueError("Unbound recovery failure metadata")
        if self.service_error_code is not None and self.failure_type is None:
            raise ValueError("Unbound service error metadata")
        return self


def validate_event_chain(events: list[LifecycleEvent], offset: int = 0) -> None:
    for index, event in enumerate(events, offset + 1):
        if event.sequence != index:
            raise ValueError("Invalid audit sequence")
    for previous, current in zip(events, events[1:], strict=False):
        if previous.phase != current.phase and current.phase not in TRANSITIONS[previous.phase]:
            raise ValueError("Illegal audit transition")


def database_target(settings: Settings) -> dict[str, Any]:
    return {
        "host": settings.database_host,
        "port": settings.database_port,
        "name": settings.database_name,
    }


def environment_target(settings: Settings) -> dict[str, Any]:
    return {
        "app_name": settings.app_name,
        "app_env": settings.app_env.value,
        "cloud_runtime": settings.cloud_runtime.value,
        "aws_region": settings.aws_region,
        "aws_endpoint_url": settings.aws_endpoint_url
        if settings.cloud_runtime.value == "localstack"
        else None,
        "tenant": settings.database_tenant_id,
    }


def expected_targets(settings: Settings, scope: RecoveryScope) -> list[JournalTarget]:
    if scope == "observability":
        if (
            settings.cloud_runtime.value != "localstack"
            or settings.app_env.value not in {"local", "test"}
            or settings.database_tenant_id is not None
        ):
            raise CredentialPreflightError(
                "Observability recovery requires its local global identity"
            )
        return [
            JournalTarget(
                runtime="observability",
                role="observability_reader",
                secret_id=f"{settings.database_secret_prefix}/local/database/observability",
                tenant=None,
            )
        ]
    if scope != "runtimes":
        raise CredentialPreflightError("Unsupported credential recovery scope")
    ids = {
        "application": settings.application_database_secret_id,
        "outbox": settings.outbox_database_secret_id,
        "remote-command": settings.remote_command_database_secret_id,
    }
    targets = []
    for runtime in DATABASE_USERS:
        role = runtime_database_user(runtime, settings.database_tenant_id)
        tenant_path = (
            f"/tenants/{role.rsplit('__', 1)[1]}" if settings.database_tenant_id is not None else ""
        )
        targets.append(
            JournalTarget(
                runtime=runtime,
                role=role,
                tenant=settings.database_tenant_id,
                secret_id=ids[runtime]
                or (
                    f"{settings.database_secret_prefix}/{settings.app_env.value}"
                    f"{tenant_path}/database/{runtime}"
                ),
            )
        )
    return targets


def validate_targets(
    settings: Settings, targets: list[dict[str, Any]], scope: RecoveryScope
) -> None:
    try:
        actual = [JournalTarget.model_validate(row) for row in targets]
        expected = expected_targets(settings, scope)
        if sorted(actual, key=lambda row: row.runtime) != sorted(
            expected, key=lambda row: row.runtime
        ):
            raise ValueError("Target set mismatch")
        if len({row.secret_id for row in actual}) != len(actual):
            raise ValueError("Duplicate Secret targets")
    except ValueError:
        raise CredentialPreflightError(
            "Credential targets do not match the configured scope"
        ) from None


def validate_journal(value: Any, settings: Settings, scope: RecoveryScope) -> dict[str, Any]:
    try:
        journal = Journal.model_validate(value)
        if (
            journal.scope != scope
            or journal.database.model_dump() != database_target(settings)
            or journal.environment.model_dump() != environment_target(settings)
        ):
            raise ValueError("Recovery context mismatch")
        validate_targets(settings, [row.target.model_dump() for row in journal.entries], scope)
    except ValueError:
        raise CredentialPreflightError(
            "Invalid recovery journal or configured target mismatch"
        ) from None
    return cast(dict[str, Any], value)


def strict_json(data: str) -> Any:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise ValueError("Duplicate JSON keys")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ValueError("Nonfinite JSON values")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def load_journal(path: Path, settings: Settings, scope: RecoveryScope) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.suffix != ".json":
            raise ValueError("Invalid journal file")
        with path.open("rb") as stream:
            data = stream.read(MAX_JOURNAL_BYTES + 1)
        if len(data) > MAX_JOURNAL_BYTES:
            raise ValueError("Oversized journal")
        value = validate_journal(strict_json(data.decode("utf-8")), settings, scope)
        from database.credential_audit import verify_archive_chain

        verify_archive_chain(path, value)
        return value
    except (ValueError, OSError):
        raise CredentialPreflightError(
            "Invalid recovery journal or configured target mismatch"
        ) from None
