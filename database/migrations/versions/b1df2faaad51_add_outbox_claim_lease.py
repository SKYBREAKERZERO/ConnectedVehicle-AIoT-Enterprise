"""add outbox claim lease

Revision ID: b1df2faaad51
Revises: 0cdc4522cc7a
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1df2faaad51"
down_revision: str | Sequence[str] | None = "0cdc4522cc7a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "outbox_events",
        sa.Column(
            "claim_token",
            sa.String(length=36),
            nullable=True,
        ),
    )
    op.add_column(
        "outbox_events",
        sa.Column(
            "lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_outbox_events_processing_lease",
        "outbox_events",
        ["status", "lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_outbox_events_processing_lease",
        table_name="outbox_events",
    )
    op.drop_column(
        "outbox_events",
        "lease_expires_at",
    )
    op.drop_column(
        "outbox_events",
        "claim_token",
    )
