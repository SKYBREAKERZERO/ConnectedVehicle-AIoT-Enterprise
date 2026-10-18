"""Bounded recovery checkpoints and immutable, hash-linked audit segments."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from database.credential_journal import (
    MAX_JOURNAL_BYTES,
    TRANSITIONS,
    Journal,
    LifecycleEvent,
    StrictRecord,
    strict_json,
    validate_event_chain,
)

CHUNK_EVENTS = 64
MAX_ARCHIVES = 1024


class AuditSegment(StrictRecord):
    operation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    offset: int = Field(ge=0)
    previous_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    events: list[LifecycleEvent] = Field(min_length=1, max_length=CHUNK_EVENTS)

    @model_validator(mode="after")
    def consistent(self) -> AuditSegment:
        if (self.offset == 0) != (self.previous_sha256 is None):
            raise ValueError("Invalid archive link")
        validate_event_chain(self.events, self.offset)
        return self


def archive_path(path: Path, operation: str, offset: int, digest: str) -> Path:
    folder = path.parent / "audit"
    if folder.is_symlink():
        raise ValueError("Invalid archive directory")
    return folder / f"{operation}-{offset}-{digest}.json"


def encoded(record: dict[str, Any]) -> bytes:
    data = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_JOURNAL_BYTES:
        raise ValueError("Credential record exceeds safe size")
    return data


def verify_archive_chain(path: Path, record: dict[str, Any]) -> int:
    offset, digest = record.get("audit_offset", 0), record.get("audit_archive_sha256")
    following = [LifecycleEvent.model_validate(row) for row in record.get("events", [])]
    for count in range(MAX_ARCHIVES):
        if offset == 0:
            return count
        if not isinstance(digest, str):
            raise ValueError("Invalid archive digest")
        target = archive_path(path, record["operation_id"], offset, digest)
        if target.is_symlink():
            raise ValueError("Invalid archive file")
        with target.open("rb") as stream:
            data = stream.read(MAX_JOURNAL_BYTES + 1)
        if len(data) > MAX_JOURNAL_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Audit archive digest mismatch")
        segment = AuditSegment.model_validate(strict_json(data.decode("utf-8")))
        if (
            segment.operation_id != record["operation_id"]
            or segment.offset + len(segment.events) != offset
        ):
            raise ValueError("Audit archive identity mismatch")
        validate_event_chain(segment.events + following[:1], segment.offset)
        following = segment.events
        offset, digest = segment.offset, segment.previous_sha256
    if offset:
        raise ValueError("Too many audit archive segments")
    return MAX_ARCHIVES


def write_segment(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Invalid archive file")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError("Audit archive already exists with different contents") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_checkpoint(
    path: Path,
    record: dict[str, Any],
    *,
    action: Literal["state", "retire_pending"] = "state",
    failure_type: str | None = None,
) -> None:
    candidate = deepcopy(record)
    if "events" in candidate:
        events = candidate["events"]
        if (
            events
            and events[-1]["phase"] != candidate["phase"]
            and candidate["phase"] not in TRANSITIONS[events[-1]["phase"]]
        ):
            raise ValueError("Illegal credential lifecycle transition")
        offset = candidate.get("audit_offset", 0)
        events.append(
            {
                "sequence": offset + len(events) + 1,
                "time": datetime.now(UTC).isoformat(),
                "phase": candidate["phase"],
                "action": action,
                "retirement_status": candidate.get("pending_retirement"),
                "failure_type": failure_type
                or candidate.get("recovery_failure_type")
                or candidate.get("failure_type"),
            }
        )
        # Validate before publishing any immutable segment. Never write a chain
        # that this reader will refuse due to its segment-count safety limit.
        Journal.model_validate(candidate)
        archive_count = verify_archive_chain(path, candidate)
        additional = (len(events) - 1) // CHUNK_EVENTS
        if archive_count + additional > MAX_ARCHIVES:
            raise ValueError("Audit archive capacity exhausted; preserve and review the operation")
        while len(events) > CHUNK_EVENTS:
            segment = {
                "operation_id": candidate["operation_id"],
                "offset": offset,
                "previous_sha256": candidate.get("audit_archive_sha256"),
                "events": events[:CHUNK_EVENTS],
            }
            AuditSegment.model_validate(segment)
            data = encoded(segment)
            digest = hashlib.sha256(data).hexdigest()
            offset += CHUNK_EVENTS
            write_segment(archive_path(path, candidate["operation_id"], offset, digest), data)
            candidate["audit_offset"], candidate["audit_archive_sha256"] = offset, digest
            del events[:CHUNK_EVENTS]
    Journal.model_validate(candidate)
    data = encoded(candidate)
    if path.is_symlink():
        raise ValueError("Invalid journal file")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    record.clear()
    record.update(candidate)
