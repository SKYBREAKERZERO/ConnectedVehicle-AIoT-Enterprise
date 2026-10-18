"""Campaign catalog metadata mirrors the forward migration; runtime writes use SQL authority."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base


class CampaignModel(Base):
    __tablename__ = "ota_campaigns"
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    release_id: Mapped[str] = mapped_column(String(36))
    status: Mapped[str] = mapped_column(Text)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB)
    signature: Mapped[str] = mapped_column(String(88))
    canary_size: Mapped[int]
    wave_size: Mapped[int]
    max_failures: Mapped[int]
    observation_seconds: Mapped[int]
    wave_timeout_seconds: Mapped[int]
    current_wave: Mapped[int] = mapped_column(server_default="-1")
    wave_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64))
    pause_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("clock_timestamp()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("clock_timestamp()")
    )
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "release_id"], ["firmware_releases.tenant_id", "firmware_releases.id"]
        ),
        CheckConstraint("status IN ('draft','frozen','running','paused','completed','cancelled')"),
        CheckConstraint("canary_size BETWEEN 1 AND 100"),
        CheckConstraint("wave_size BETWEEN 1 AND 100"),
        CheckConstraint("max_failures>=0 AND max_failures<canary_size"),
        CheckConstraint("observation_seconds BETWEEN 0 AND 3600"),
        CheckConstraint("wave_timeout_seconds BETWEEN 30 AND 86400"),
        CheckConstraint("current_wave>=-1"),
        Index("ix_campaign_running", "tenant_id", "status", "id"),
    )


class CampaignTargetModel(Base):
    __tablename__ = "ota_campaign_targets"
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ecu_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vehicle_id: Mapped[str] = mapped_column(String(36))
    wave: Mapped[int]
    job_id: Mapped[str] = mapped_column(String(36))
    dispatched: Mapped[bool] = mapped_column(Boolean, server_default="false")
    firmware_version: Mapped[str] = mapped_column(String(64))
    security_version: Mapped[int] = mapped_column(BigInteger)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "campaign_id"], ["ota_campaigns.tenant_id", "ota_campaigns.id"]
        ),
        ForeignKeyConstraint(
            ["tenant_id", "ecu_id"], ["ecu_inventory.tenant_id", "ecu_inventory.id"]
        ),
        UniqueConstraint("tenant_id", "job_id"),
        CheckConstraint("wave>=0"),
        CheckConstraint("security_version>=0"),
        Index("ix_campaign_wave", "tenant_id", "campaign_id", "wave", "dispatched"),
    )


class CampaignEventModel(Base):
    __tablename__ = "ota_campaign_events"
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    operation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(36))
    request: Mapped[dict[str, Any]] = mapped_column(JSONB)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("clock_timestamp()")
    )
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "campaign_id"], ["ota_campaigns.tenant_id", "ota_campaigns.id"]
        ),
    )
