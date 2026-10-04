from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base


class RemoteCommandModel(Base):
    __tablename__ = "remote_commands"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    vehicle_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "vehicles.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    tenant_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    command_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    idempotency_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "command_type IN ('lock', 'unlock', 'start', 'stop', 'honk', 'flash_lights')",
            name="ck_remote_commands_command_type_valid",
        ),
        CheckConstraint(
            "status IN ("
            "'requested', "
            "'queued', "
            "'dispatching', "
            "'sent', "
            "'acknowledged', "
            "'succeeded', "
            "'failed', "
            "'timed_out', "
            "'expired', "
            "'cancelled'"
            ")",
            name="ck_remote_commands_status_valid",
        ),
        UniqueConstraint(
            "tenant_id",
            "vehicle_id",
            "idempotency_key",
            name="uq_remote_commands_tenant_vehicle_idempotency",
        ),
        Index(
            "ix_remote_commands_tenant_vehicle_created",
            "tenant_id",
            "vehicle_id",
            "created_at",
        ),
        Index(
            "ix_remote_commands_status_expires",
            "status",
            "expires_at",
        ),
    )
