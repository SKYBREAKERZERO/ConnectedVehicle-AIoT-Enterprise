from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base


class CommandReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    status: Literal["acknowledged", "succeeded", "failed"]
    occurred_at: AwareDatetime
    failure_code: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")

    @model_validator(mode="after")
    def timestamp_and_failure(self) -> CommandReport:
        if self.occurred_at > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("Report time is in the future.")
        if (self.status == "failed") != bool(self.failure_code):
            raise ValueError("Only failed reports require a failure code.")
        return self


class TelemetrySample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    measured_at: AwareDatetime
    speed_kph: float = Field(ge=0, le=300, allow_inf_nan=False)
    battery_percent: float = Field(ge=0, le=100, allow_inf_nan=False)
    temperature_c: float = Field(ge=-80, le=180, allow_inf_nan=False)

    @model_validator(mode="after")
    def fresh_sample(self) -> TelemetrySample:
        now = datetime.now(UTC)
        if not now - timedelta(days=1) <= self.measured_at <= now + timedelta(minutes=5):
            raise ValueError("Telemetry timestamp is outside the ingestion window.")
        return self


class CommandReportModel(Base):
    __tablename__ = "command_reports"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    command_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remote_commands.id"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    vehicle_id: Mapped[str] = mapped_column(String(36), ForeignKey("vehicles.id"), nullable=False)
    report: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TelemetrySampleModel(Base):
    __tablename__ = "telemetry_samples"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    vehicle_id: Mapped[str] = mapped_column(String(36), ForeignKey("vehicles.id"), nullable=False)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sample: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    __table_args__ = (
        Index(
            "ix_telemetry_tenant_vehicle_measured",
            "tenant_id",
            "vehicle_id",
            "measured_at",
            "event_id",
        ),
    )
