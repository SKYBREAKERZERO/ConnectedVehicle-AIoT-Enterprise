"""Fixed login tenant binding for dedicated tenant runtimes."""

from pathlib import Path

from alembic import op

revision = "b48f720da63e"
down_revision = "a37e610c952d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    directory = Path(__file__).resolve().parents[1] / "sql"
    for statement in (
        (directory / "b48f720da63e-tenant-bindings.sql").read_text(encoding="utf-8").split(";")
    ):
        if statement.strip():
            op.execute(statement)
    for statement in (
        (directory / "b48f720da63e-operational-health.sql").read_text(encoding="utf-8").split(";")
    ):
        if statement.strip():
            op.execute(statement)
    for table in (
        "vehicles",
        "remote_commands",
        "command_reports",
        "telemetry_samples",
        "outbox_events",
    ):
        predicate = (
            "tenant_id = COALESCE(public.runtime_tenant_binding(), "
            "nullif(current_setting('app.tenant_id', true), ''))"
        )
        if table == "outbox_events":
            predicate = "current_user = 'outbox_worker' OR " + predicate
        op.execute(f"DROP POLICY tenant_guard ON {table}")
        op.execute(
            f"CREATE POLICY tenant_guard ON {table} AS RESTRICTIVE "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade() -> None:
    raise RuntimeError("Security contract requires a reviewed forward migration")
