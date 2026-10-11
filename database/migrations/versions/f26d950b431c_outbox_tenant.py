"""Derive and index immutable outbox tenant ownership."""

from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision = "f26d950b431c"
down_revision = "e15c849a320b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE OR REPLACE FUNCTION public.outbox_event_tenant(body text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    RETURN body::jsonb -> 'payload' ->> 'tenant_id';
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$;
"""
    )
    op.add_column(
        "outbox_events",
        sa.Column(
            "tenant_id",
            sa.String(255),
            sa.Computed("public.outbox_event_tenant(event_body)", persisted=True),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_outbox_tenant_nonblank",
        "outbox_events",
        "tenant_id IS NULL OR (length(tenant_id) > 0 AND tenant_id = trim(tenant_id))",
    )
    op.create_index("ix_outbox_events_tenant_status", "outbox_events", ["tenant_id", "status"])
    source = Path(__file__).resolve().parents[2] / "outbox-tenant-policy.sql"
    for statement in source.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            op.execute(statement)


def downgrade() -> None:
    source = Path(__file__).resolve().parents[2] / "tenant-rls.sql"
    # Restore the payload-derived guard before removing its replacement column.
    outbox = source.read_text(encoding="utf-8").split("ALTER TABLE outbox_events", 1)[1]
    for statement in ("ALTER TABLE outbox_events" + outbox).split(";"):
        if statement.strip():
            op.execute(statement)
    op.drop_index("ix_outbox_events_tenant_status", table_name="outbox_events")
    op.drop_constraint("ck_outbox_tenant_nonblank", "outbox_events", type_="check")
    op.drop_column("outbox_events", "tenant_id")
    op.execute("DROP FUNCTION IF EXISTS public.outbox_event_tenant(text)")
