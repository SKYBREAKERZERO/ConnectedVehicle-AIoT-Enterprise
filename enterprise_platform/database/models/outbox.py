from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    DDL,
    CheckConstraint,
    Computed,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base
from enterprise_platform.reliability.outbox import OutboxStatus


class OutboxEventModel(Base):
    __tablename__ = "outbox_events"
    # API has INSERT-only access; do not fetch the generated column with RETURNING.
    __mapper_args__ = {"eager_defaults": False}

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    event_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    destination: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    event_body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Database-derived ownership cannot diverge from the immutable event payload.
    tenant_id: Mapped[str | None] = mapped_column(
        String(255),
        Computed("public.outbox_event_tenant(event_body)", persisted=True),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=OutboxStatus.PENDING.value,
    )

    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    claim_token: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )

    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    failure_code: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    failure_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            "tenant_id IS NULL OR (length(tenant_id) > 0 AND tenant_id = trim(tenant_id))",
            name="ck_outbox_tenant_nonblank",
        ),
        Index("ix_outbox_events_tenant_status", "tenant_id", "status"),
        Index(
            "ix_outbox_events_pending_available",
            "status",
            "available_at",
        ),
        Index(
            "ix_outbox_events_processing_lease",
            "status",
            "lease_expires_at",
        ),
    )


# Preserve quarantinable malformed legacy events without granting runtime DDL.
event.listen(
    OutboxEventModel.__table__,
    "before_create",
    DDL(  # type: ignore[no-untyped-call]  # SQLAlchemy DDL constructor lacks typed stubs.
        """CREATE OR REPLACE FUNCTION public.outbox_event_tenant(body text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    RETURN body::jsonb -> 'payload' ->> 'tenant_id';
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$;
"""
    ).execute_if(dialect="postgresql"),
)
