"""Device result ledger and append-only tenant telemetry."""

import sqlalchemy as sa
from alembic import op

revision = "c7a018d3f219"
down_revision = "a52bcd546e2d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "command_reports",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("command_id", sa.String(36), sa.ForeignKey("remote_commands.id"), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("vehicle_id", sa.String(36), sa.ForeignKey("vehicles.id"), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "telemetry_samples",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("vehicle_id", sa.String(36), sa.ForeignKey("vehicles.id"), nullable=False),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sample", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_telemetry_tenant_vehicle_measured",
        "telemetry_samples",
        ["tenant_id", "vehicle_id", "measured_at", "event_id"],
    )


def downgrade() -> None:
    op.drop_table("telemetry_samples")
    op.drop_table("command_reports")
