"""Admin-only managed SQS redrive with a durable intent and no blind retry."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from enterprise_platform.database.models.operations import OperatorActionModel


class RedriveClient(Protocol):
    def get_queue_attributes(
        self, *, QueueUrl: str, AttributeNames: list[str]
    ) -> dict[str, object]: ...
    def start_message_move_task(
        self, *, SourceArn: str, DestinationArn: str, MaxNumberOfMessagesPerSecond: int
    ) -> dict[str, object]: ...
    def list_message_move_tasks(self, *, SourceArn: str, MaxResults: int) -> dict[str, object]: ...


async def redrive(
    sessions: async_sessionmaker[AsyncSession],
    client: RedriveClient,
    *,
    source_url: str,
    destination_url: str,
    operation_id: str,
    actor: str,
    reason: str,
    rate: int = 1,
    apply: bool = False,
    allow_bulk: bool = False,
) -> dict[str, object]:
    operation_id = str(UUID(operation_id))
    if not actor.strip() or not reason.strip() or len(actor) > 255 or len(reason) > 1000:
        raise ValueError("A bounded operator identity and incident reason are required.")
    if not 1 <= rate <= 10:
        raise ValueError("Operational redrive rate must be 1-10 messages per second.")
    source = await asyncio.to_thread(
        client.get_queue_attributes, QueueUrl=source_url, AttributeNames=["QueueArn"]
    )
    destination = await asyncio.to_thread(
        client.get_queue_attributes,
        QueueUrl=destination_url,
        AttributeNames=["QueueArn", "RedrivePolicy"],
    )
    source_attrs = source.get("Attributes")
    destination_attrs = destination.get("Attributes")
    if not isinstance(source_attrs, dict) or not isinstance(destination_attrs, dict):
        raise ValueError("Queue attributes are unavailable.")
    source_arn, destination_arn = source_attrs.get("QueueArn"), destination_attrs.get("QueueArn")
    if not isinstance(source_arn, str) or not isinstance(destination_arn, str):
        raise ValueError("Queue ARNs are unavailable.")
    policy = json.loads(str(destination_attrs.get("RedrivePolicy", "{}")))
    if policy.get("deadLetterTargetArn") != source_arn or source_arn == destination_arn:
        raise ValueError("Destination must be the original queue associated with this DLQ.")
    evidence = {"source_arn": source_arn, "destination_arn": destination_arn, "rate": rate}
    digest = sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    if not apply:
        return evidence | {
            "operation_id": operation_id,
            "dry_run": True,
            "bulk_review_required": True,
        }
    if not allow_bulk:
        raise ValueError("Managed redrive moves the whole DLQ; explicit bulk review is required.")
    async with sessions() as session, session.begin():
        # Commit intent BEFORE the external action. A timeout leaves an ambiguous intent,
        # which must be reconciled against ListMessageMoveTasks rather than retried.
        existing = await session.get(OperatorActionModel, operation_id)
        if existing:
            if existing.action != "dlq_redrive" or existing.payload_hash != digest:
                raise ValueError("Operation ID belongs to another action.")
            if existing.state == "intent":
                raise ValueError(
                    "Ambiguous redrive intent: inspect AWS tasks before another operation."
                )
            return existing.evidence | {"operation_id": operation_id, "already_started": True}
        session.add(
            OperatorActionModel(
                operation_id=operation_id,
                actor=actor,
                reason=reason,
                action="dlq_redrive",
                target_id=source_arn,
                payload_hash=digest,
                state="intent",
                evidence=evidence,
                created_at=datetime.now(UTC),
            )
        )
    response = await asyncio.to_thread(
        client.start_message_move_task,
        SourceArn=source_arn,
        DestinationArn=destination_arn,
        MaxNumberOfMessagesPerSecond=rate,
    )
    handle = response.get("TaskHandle")
    if not isinstance(handle, str) or not handle:
        raise ValueError("AWS did not confirm a redrive handle; reconcile the intent.")
    async with sessions() as session, session.begin():
        action = await session.scalar(
            select(OperatorActionModel)
            .where(OperatorActionModel.operation_id == operation_id)
            .with_for_update()
        )
        assert action is not None
        action.state = "started"
        action.evidence = evidence | {"task_handle": handle}
    return evidence | {"operation_id": operation_id, "task_handle": handle, "state": "started"}


async def redrive_status(
    sessions: async_sessionmaker[AsyncSession], client: RedriveClient, *, operation_id: str
) -> dict[str, object]:
    async with sessions() as session:
        action = await session.get(OperatorActionModel, str(UUID(operation_id)))
        if not action or action.action != "dlq_redrive":
            raise ValueError("Audited redrive operation was not found.")
        source = str(action.evidence["source_arn"])
        handle = action.evidence.get("task_handle")
    tasks = await asyncio.to_thread(client.list_message_move_tasks, SourceArn=source, MaxResults=10)
    results = tasks.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Invalid AWS task list.")
    for task in results:
        if isinstance(task, dict) and handle and task.get("TaskHandle") == handle:
            result = {
                key: task.get(key)
                for key in (
                    "Status",
                    "ApproximateNumberOfMessagesMoved",
                    "ApproximateNumberOfMessagesToMove",
                    "StartedTimestamp",
                    "FailureReason",
                )
            }
            # Task metadata only; never export message bodies or secret values.
            async with sessions() as session, session.begin():
                action = await session.scalar(
                    select(OperatorActionModel)
                    .where(OperatorActionModel.operation_id == str(UUID(operation_id)))
                    .with_for_update()
                )
                assert action
                status = str(task.get("Status", "UNKNOWN"))
                action.state = {
                    "COMPLETED": "complete",
                    "FAILED": "failed",
                    "CANCELLED": "cancelled",
                }.get(status, "started")
                action.evidence = action.evidence | {"last_observation": result}
            return result
    return {"state": "unresolved", "intent_requires_manual_reconciliation": True}
