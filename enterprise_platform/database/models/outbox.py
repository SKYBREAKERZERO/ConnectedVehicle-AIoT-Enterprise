from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base
from enterprise_platform.reliability.outbox import OutboxStatus


class OutboxEventModel(Base):
    __tablename__ = "outbox_events"

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

    __table_args__ = (
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
