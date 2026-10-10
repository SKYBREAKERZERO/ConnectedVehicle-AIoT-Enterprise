"""Audited administrative reconciliation/replay. Dry-run by default; no runtime credentials."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from connected_vehicle import device_data as _device_models  # noqa: F401
from connected_vehicle.remote_command.events import REMOTE_COMMAND_DESTINATION
from connected_vehicle.remote_command.persistence.models import RemoteCommandModel
from connected_vehicle.vehicle.persistence import models as _vehicle_models  # noqa: F401
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
            or event.event_type != "vehicle.command.requested"
        ):
            raise ValueError("Only validated remote-command events can be replayed.")
        command = await session.get(RemoteCommandModel, str(UUID(str(event.payload["command_id"]))))
        if (
            command is None
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
        else:
            result = await replay_outbox(
                sessions,
                outbox_id=args.id,
                operation_id=args.operation_id,
                actor=args.actor,
                reason=args.reason,
                expected_attempts=args.expected_attempts,
                apply=args.apply,
            )
        print(json.dumps(result, default=str, indent=2))
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("reconcile")
    replay = commands.add_parser("outbox-replay")
    for name in ("id", "operation-id", "actor", "reason"):
        replay.add_argument("--" + name, required=True)
    replay.add_argument("--expected-attempts", type=int, required=True)
    replay.add_argument("--apply", action="store_true")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
