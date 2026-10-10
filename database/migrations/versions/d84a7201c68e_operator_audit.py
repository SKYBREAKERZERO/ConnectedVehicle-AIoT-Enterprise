"""Operator action audit, never granted to runtime roles."""

import sqlalchemy as sa
from alembic import op

revision = "d84a7201c68e"
down_revision = "c7a018d3f219"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operator_actions",
        sa.Column("operation_id", sa.String(36), primary_key=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("operator_actions")
