"""Audited administrative reconciliation/replay. Dry-run by default; no runtime credentials."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle import device_data as _device_models  # noqa: F401
from connected_vehicle.remote_command.domain import RemoteCommandId, RemoteCommandStatus
from connected_vehicle.remote_command.events import (
    REMOTE_COMMAND_DESTINATION,
    REMOTE_COMMAND_EVENT_SOURCE,
    REMOTE_COMMAND_REQUESTED_EVENT_TYPE,
)
from connected_vehicle.remote_command.persistence.models import RemoteCommandModel
from connected_vehicle.remote_command.persistence.repository import (
    SQLAlchemyRemoteCommandRepository,
)
from connected_vehicle.remote_command.wire_contracts import RequestedPayload
from connected_vehicle.vehicle.persistence import models as _vehicle_models  # noqa: F401
from database.dlq_operations import RedriveClient, redrive, redrive_status
from enterprise_platform.cloud.client_factory import AWSClientFactory
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import migration_database_settings
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.models.operations import OperatorActionModel
from enterprise_platform.database.models.outbox import OutboxEventModel
from enterprise_platform.database.session import create_session_factory
from enterprise_platform.messaging.serialization import deserialize_event_envelope
from enterprise_platform.reliability.outbox import OutboxStatus


async def reconcile(sessions: async_sessionmaker[AsyncSession]) -> dict[str, object]:
    now = datetime.now(UTC)
    async with sessions() as session:
        counts = dict(
            (
                await session.execute(
                    select(OutboxEventModel.status, func.count()).group_by(OutboxEventModel.status)
                )
            ).all()
        )
        expired_leases = await session.scalar(
            select(func.count())
            .select_from(OutboxEventModel)
            .where(OutboxEventModel.status == "processing", OutboxEventModel.lease_expires_at < now)
        )
        delivery_timeouts = await session.scalar(
            select(func.count())
            .select_from(RemoteCommandModel)
            .where(
                RemoteCommandModel.status.in_(["sent", "acknowledged", "dispatching"]),
                RemoteCommandModel.expires_at < now,
            )
        )
        return {
            "outbox_status_counts": counts,
            "expired_outbox_leases": expired_leases,
            "commands_past_execution_deadline": delivery_timeouts,
        }


async def timeout_commands(
    sessions: async_sessionmaker[AsyncSession],
    *,
    actor: str,
    reason: str,
    apply: bool = False,
    limit: int = 100,
) -> dict[str, object]:
    if not actor.strip() or not reason.strip() or len(actor) > 255 or len(reason) > 1000:
        raise ValueError("A bounded operator identity and incident reason are required.")
    if not 1 <= limit <= 100:
        raise ValueError("Timeout reconciliation batch must be 1-100 commands.")
    now = datetime.now(UTC)
    async with sessions() as session, session.begin():
        rows = list(
            (
                await session.scalars(
                    select(RemoteCommandModel)
                    .where(
                        RemoteCommandModel.status.in_(["sent", "acknowledged", "dispatching"]),
                        RemoteCommandModel.expires_at < now,
                    )
                    .order_by(RemoteCommandModel.expires_at)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        repository = SQLAlchemyRemoteCommandRepository(session)
        ids = [row.id for row in rows]
        if apply:
            for row in rows:
                previous_status = row.status
                command = await repository.get_for_update(RemoteCommandId(row.id))
                assert command
                await repository.save(
                    command.transition_to(
                        RemoteCommandStatus.TIMED_OUT, now=max(now, command.updated_at)
                    )
                )
                session.add(
                    OperatorActionModel(
                        operation_id=str(uuid4()),
                        actor=actor,
                        reason=reason,
                        action="command_timeout",
                        target_id=row.id,
                        payload_hash="",
                        state="complete",
                        evidence={"previous_status": previous_status},
                        created_at=now,
                    )
                )
        return {"command_ids": ids, "count": len(ids), "dry_run": not apply}


async def replay_outbox(
    sessions: async_sessionmaker[AsyncSession],
    *,
    outbox_id: str,
    operation_id: str,
    actor: str,
    reason: str,
    expected_attempts: int,
    apply: bool = False,
) -> dict[str, object]:
    operation_id = str(UUID(operation_id))
    if not actor.strip() or not reason.strip() or len(actor) > 255 or len(reason) > 1000:
        raise ValueError("Replay requires a bounded operator identity and reason.")
    async with sessions() as session, session.begin():
        # Admin only. Runtime IAM and database roles never get this entry point.
        row = await session.scalar(
            select(OutboxEventModel)
            .where(OutboxEventModel.id == str(UUID(outbox_id)))
            .with_for_update()
        )
        if row is None:
            raise ValueError("Outbox record was not found.")
        digest = sha256(row.event_body.encode()).hexdigest()
        previous = await session.get(OperatorActionModel, operation_id)
        if previous:
            if (
                previous.target_id != row.id
                or previous.action != "outbox_replay"
                or previous.payload_hash != digest
            ):
                raise ValueError("Operation ID already identifies a different action.")
            return {"operation_id": operation_id, "already_applied": True}
        if row.status != OutboxStatus.FAILED.value or row.attempts != expected_attempts:
            raise ValueError("Replay requires FAILED state and the expected attempt count.")
        event = deserialize_event_envelope(row.event_body)
        if (
            row.destination != REMOTE_COMMAND_DESTINATION
            or event.event_type != REMOTE_COMMAND_REQUESTED_EVENT_TYPE
            or event.source != REMOTE_COMMAND_EVENT_SOURCE
            or event.schema_version != "1.0"
        ):
            raise ValueError("Only validated remote-command events can be replayed.")
        payload = RequestedPayload.model_validate(event.payload)
        if event.event_id != f"remote-command:{payload.command_id}:requested":
            raise ValueError("Invalid deterministic event identity.")
        command = await session.scalar(
            select(RemoteCommandModel)
            .where(RemoteCommandModel.id == str(payload.command_id))
            .with_for_update()
        )
        if (
            command is None
            or command.tenant_id != payload.tenant_id
            or command.vehicle_id != str(payload.vehicle_id)
            or command.command_type != payload.command_type.value
            or command.created_at != payload.created_at
            or command.expires_at != payload.expires_at
            or command.expires_at <= datetime.now(UTC)
            or command.status not in {"requested", "queued", "dispatching"}
        ):
            raise ValueError(
                "Command is expired, terminal, already sent, or missing; "
                "issue a new command deliberately."
            )
        result: dict[str, object] = {
            "operation_id": operation_id,
            "outbox_id": row.id,
            "payload_sha256": digest,
            "previous_attempts": row.attempts,
            "dry_run": not apply,
        }
        if apply:
            session.add(
                OperatorActionModel(
                    operation_id=operation_id,
                    actor=actor,
                    reason=reason,
                    action="outbox_replay",
                    target_id=row.id,
                    payload_hash=digest,
                    state="complete",
                    evidence={
                        "previous_attempts": row.attempts,
                        "previous_failure_code": row.failure_code or "",
                    },
                    created_at=datetime.now(UTC),
                )
            )
            row.status = "pending"
            row.attempts = 0
            row.available_at = datetime.now(UTC)
            row.failed_at = row.failure_code = row.failure_reason = None
            row.claim_token = None
            row.lease_expires_at = None
        return result


async def run(args: argparse.Namespace) -> None:
    engine = create_database_engine(migration_database_settings(Settings()))
    try:
        sessions = create_session_factory(engine)
        if args.action == "reconcile":
            result = await reconcile(sessions)
        elif args.action == "command-timeouts":
            result = await timeout_commands(
                sessions, actor=args.actor, reason=args.reason, apply=args.apply, limit=args.limit
            )
        elif args.action == "outbox-replay":
            result = await replay_outbox(
                sessions,
                outbox_id=args.id,
                operation_id=args.operation_id,
                actor=args.actor,
                reason=args.reason,
                expected_attempts=args.expected_attempts,
                apply=args.apply,
            )
        else:
            client = cast(
                RedriveClient,
                AWSClientFactory(Settings().model_copy(update={"aws_max_attempts": 1})).sqs(),
            )
            if args.action == "dlq-status":
                result = await redrive_status(sessions, client, operation_id=args.operation_id)
            else:
                result = await redrive(
                    sessions,
                    client,
                    source_url=args.source_url,
                    destination_url=args.destination_url,
                    operation_id=args.operation_id,
                    actor=args.actor,
                    reason=args.reason,
                    rate=args.rate,
                    apply=args.apply,
                    allow_bulk=args.allow_bulk,
                )
        print(json.dumps(result, default=str, indent=2))
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("reconcile")
    timeouts = commands.add_parser("command-timeouts")
    timeouts.add_argument("--actor", required=True)
    timeouts.add_argument("--reason", required=True)
    timeouts.add_argument("--limit", type=int, default=100)
    timeouts.add_argument("--apply", action="store_true")
    replay = commands.add_parser("outbox-replay")
    for name in ("id", "operation-id", "actor", "reason"):
        replay.add_argument("--" + name, required=True)
    replay.add_argument("--expected-attempts", type=int, required=True)
    replay.add_argument("--apply", action="store_true")
    dlq = commands.add_parser("dlq-redrive")
    for name in ("source-url", "destination-url", "operation-id", "actor", "reason"):
        dlq.add_argument("--" + name, required=True)
    dlq.add_argument("--rate", type=int, default=1)
    dlq.add_argument("--allow-bulk", action="store_true")
    dlq.add_argument("--apply", action="store_true")
    status = commands.add_parser("dlq-status")
    status.add_argument("--operation-id", required=True)
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
