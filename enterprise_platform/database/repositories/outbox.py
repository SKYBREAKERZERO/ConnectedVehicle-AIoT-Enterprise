from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from enterprise_platform.database.models.outbox import (
    OutboxEventModel,
)
from enterprise_platform.reliability.outbox import (
    ClaimedOutboxEvent,
    OutboxStatus,
    PendingOutboxEvent,
)


class SQLAlchemyOutboxRepository:
    """Persists and claims outbox events inside an existing transaction."""

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self._session = session

    def add(
        self,
        event: PendingOutboxEvent,
    ) -> OutboxEventModel:
        model = OutboxEventModel(
            event_id=event.event_id,
            event_type=event.event_type,
            destination=event.destination,
            event_body=event.event_body,
            status=OutboxStatus.PENDING.value,
            attempts=0,
            created_at=event.created_at,
            available_at=event.available_at,
            claim_token=None,
            lease_expires_at=None,
            published_at=None,
        )

        self._session.add(model)

        return model

    async def claim_batch(
        self,
        *,
        batch_size: int = 100,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> tuple[ClaimedOutboxEvent, ...]:
        if not 1 <= batch_size <= 1000:
            raise ValueError("Outbox batch_size must be between 1 and 1000.")

        if lease_seconds < 1:
            raise ValueError("Outbox lease_seconds must be at least 1.")

        resolved_now = now if now is not None else datetime.now(UTC)

        if resolved_now.tzinfo is None:
            raise ValueError("Outbox claim time must be timezone-aware.")

        statement = (
            select(OutboxEventModel)
            .where(
                or_(
                    and_(
                        OutboxEventModel.status == OutboxStatus.PENDING.value,
                        OutboxEventModel.available_at <= resolved_now,
                    ),
                    and_(
                        OutboxEventModel.status == OutboxStatus.PROCESSING.value,
                        OutboxEventModel.lease_expires_at.is_not(None),
                        OutboxEventModel.lease_expires_at <= resolved_now,
                    ),
                )
            )
            .order_by(
                OutboxEventModel.available_at,
                OutboxEventModel.created_at,
                OutboxEventModel.id,
            )
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )

        result = await self._session.execute(statement)

        models = list(result.scalars())

        claimed: list[ClaimedOutboxEvent] = []

        for model in models:
            claim_token = str(uuid4())

            lease_expires_at = resolved_now + timedelta(seconds=lease_seconds)

            model.status = OutboxStatus.PROCESSING.value
            model.attempts += 1
            model.claim_token = claim_token
            model.lease_expires_at = lease_expires_at

            claimed.append(
                ClaimedOutboxEvent(
                    id=model.id,
                    event_id=model.event_id,
                    event_type=model.event_type,
                    destination=model.destination,
                    event_body=model.event_body,
                    attempts=model.attempts,
                    claim_token=claim_token,
                    lease_expires_at=lease_expires_at,
                )
            )

        return tuple(claimed)

    async def mark_published(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        published_at: datetime | None = None,
    ) -> bool:
        normalized_outbox_id = outbox_id.strip()
        normalized_claim_token = claim_token.strip()

        if not normalized_outbox_id:
            raise ValueError("Outbox id must not be empty.")

        if not normalized_claim_token:
            raise ValueError("Outbox claim token must not be empty.")

        resolved_published_at = published_at if published_at is not None else datetime.now(UTC)

        if resolved_published_at.tzinfo is None:
            raise ValueError("Outbox published_at must be timezone-aware.")

        statement = (
            update(OutboxEventModel)
            .where(
                OutboxEventModel.id == normalized_outbox_id,
                OutboxEventModel.status == OutboxStatus.PROCESSING.value,
                OutboxEventModel.claim_token == normalized_claim_token,
            )
            .values(
                status=OutboxStatus.PUBLISHED.value,
                claim_token=None,
                lease_expires_at=None,
                published_at=resolved_published_at,
            )
            .returning(OutboxEventModel.id)
        )

        result = await self._session.execute(statement)

        return result.scalar_one_or_none() is not None

    async def schedule_retry(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        available_at: datetime,
    ) -> bool:
        normalized_outbox_id = outbox_id.strip()
        normalized_claim_token = claim_token.strip()

        if not normalized_outbox_id:
            raise ValueError("Outbox id must not be empty.")

        if not normalized_claim_token:
            raise ValueError("Outbox claim token must not be empty.")

        if available_at.tzinfo is None:
            raise ValueError("Outbox available_at must be timezone-aware.")

        statement = (
            update(OutboxEventModel)
            .where(
                OutboxEventModel.id == normalized_outbox_id,
                OutboxEventModel.status == OutboxStatus.PROCESSING.value,
                OutboxEventModel.claim_token == normalized_claim_token,
            )
            .values(
                status=OutboxStatus.PENDING.value,
                available_at=available_at,
                claim_token=None,
                lease_expires_at=None,
            )
            .returning(OutboxEventModel.id)
        )

        result = await self._session.execute(statement)

        return result.scalar_one_or_none() is not None

    async def mark_failed(
        self,
        *,
        outbox_id: str,
        claim_token: str,
        failed_at: datetime,
        failure_code: str,
    ) -> bool:
        if not outbox_id.strip() or not claim_token.strip():
            raise ValueError("Outbox ID and claim token must not be blank.")
        if failed_at.tzinfo is None:
            raise ValueError("Outbox failed_at must be timezone-aware.")
        if failure_code not in {"non_retryable", "retry_exhausted"}:
            raise ValueError("Unsupported outbox failure code.")
        result = await self._session.execute(
            update(OutboxEventModel)
            .where(
                OutboxEventModel.id == outbox_id,
                OutboxEventModel.status == OutboxStatus.PROCESSING.value,
                OutboxEventModel.claim_token == claim_token,
            )
            .values(
                status=OutboxStatus.FAILED.value,
                claim_token=None,
                lease_expires_at=None,
                failed_at=failed_at,
                failure_code=failure_code,
                failure_reason="Publication failed; inspect sanitized worker telemetry.",
            )
            .returning(OutboxEventModel.id)
        )
        return result.scalar_one_or_none() is not None
