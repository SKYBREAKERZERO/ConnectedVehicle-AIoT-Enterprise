from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base


class VehicleModel(Base):
    __tablename__ = "vehicles"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    vin: Mapped[str] = mapped_column(
        String(17),
        nullable=False,
        unique=True,
    )

    tenant_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
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

    __table_args__ = (
        CheckConstraint(
            "status IN ('provisioning', 'active', 'suspended', 'decommissioned')",
            name="ck_vehicles_status_valid",
        ),
        Index(
            "ix_vehicles_tenant_status",
            "tenant_id",
            "status",
        ),
    )
