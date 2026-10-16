from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from enterprise_platform.database.base import Base


class Identity:
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)


class Creation:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)


class ECUModel(Identity, Creation, Base):
    __tablename__ = "ecu_inventory"
    vehicle_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecu_type: Mapped[str] = mapped_column(String(64), nullable=False)
    hardware_version: Mapped[str] = mapped_column(String(64), nullable=False)
    firmware_version: Mapped[str] = mapped_column(String(64), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "vehicle_id"],
            ["vehicles.tenant_id", "vehicles.id"],
            name="fk_ecu_vehicle_tenant",
        ),
        UniqueConstraint("tenant_id", "serial_number", name="uq_ecu_serial"),
        UniqueConstraint(
            "tenant_id", "vehicle_id", "id", "ecu_type", "hardware_version", name="uq_ecu_target"
        ),
        Index("ix_ecu_vehicle", "tenant_id", "vehicle_id", "id"),
    )


class FirmwareModel(Identity, Creation, Base):
    __tablename__ = "firmware_releases"
    ecu_type: Mapped[str] = mapped_column(String(64), nullable=False)
    hardware_version: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    artifact_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    artifact_version: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_firmware_idempotency"),
        UniqueConstraint(
            "tenant_id", "ecu_type", "hardware_version", "version", name="uq_firmware_version"
        ),
        UniqueConstraint(
            "tenant_id", "id", "ecu_type", "hardware_version", name="uq_firmware_target"
        ),
        CheckConstraint("size_bytes > 0 AND size_bytes <= 4294967296", name="ck_firmware_size"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_firmware_sha256"),
        CheckConstraint(
            "artifact_version <> '' AND artifact_version <> 'null'", name="ck_firmware_pinned"
        ),
    )


class JobModel(Identity, Creation, Base):
    __tablename__ = "ota_jobs"
    vehicle_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecu_id: Mapped[str] = mapped_column(String(36), nullable=False)
    release_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecu_type: Mapped[str] = mapped_column(String(64), nullable=False)
    hardware_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "vehicle_id", "ecu_id", "ecu_type", "hardware_version"],
            [
                "ecu_inventory.tenant_id",
                "ecu_inventory.vehicle_id",
                "ecu_inventory.id",
                "ecu_inventory.ecu_type",
                "ecu_inventory.hardware_version",
            ],
            name="fk_job_ecu",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "release_id", "ecu_type", "hardware_version"],
            [
                "firmware_releases.tenant_id",
                "firmware_releases.id",
                "firmware_releases.ecu_type",
                "firmware_releases.hardware_version",
            ],
            name="fk_job_release",
        ),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_job_idempotency"),
        CheckConstraint("status IN ('pending_verification','cancelled')", name="ck_ota_job_status"),
        Index(
            "uq_ota_active_ecu",
            "tenant_id",
            "ecu_id",
            unique=True,
            postgresql_where=text("status = 'pending_verification'"),
        ),
        Index("ix_ota_vehicle", "tenant_id", "vehicle_id", "ecu_id", "id"),
    )


class OTAAuditModel(Identity, Base):
    __tablename__ = "ota_audit_events"
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    operation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "resource_type", "action", "operation_key", name="uq_ota_audit_operation"
        ),
    )
