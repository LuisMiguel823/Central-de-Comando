"""applications: perfil de integracao e relatorio devolvido pelo sistema

Revision ID: c3a9f1e07b52
Revises: b7d2e41c9a3f
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c3a9f1e07b52"
down_revision: Union[str, None] = "b7d2e41c9a3f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("stack", sa.String(40), nullable=True))
    op.add_column(
        "applications",
        sa.Column("multi_client", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "applications",
        sa.Column("has_local_access", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("applications", sa.Column("integration_report", sa.JSON(), nullable=True))
    op.add_column("applications", sa.Column("integration_reported_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    for col in ("integration_reported_at", "integration_report", "has_local_access", "multi_client", "stack"):
        op.drop_column("applications", col)
