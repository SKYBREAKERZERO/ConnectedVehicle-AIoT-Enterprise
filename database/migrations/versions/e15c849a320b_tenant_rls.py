"""Tenant row security, applied only with migration-owner credentials."""

from pathlib import Path

from alembic import op

revision = "e15c849a320b"
down_revision = "d84a7201c68e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    source = Path(__file__).resolve().parents[2] / "tenant-rls.sql"
    for statement in source.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            op.execute(statement)


def downgrade() -> None:
    for table in (
        "vehicles",
        "remote_commands",
        "command_reports",
        "telemetry_samples",
        "outbox_events",
    ):
        op.execute(f"DROP POLICY IF EXISTS tenant_guard ON {table}")
        op.execute(f"DROP POLICY IF EXISTS runtime_access ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
