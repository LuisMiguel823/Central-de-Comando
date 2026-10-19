"""applications: require_access (so entra quem tem permissao concedida no modulo)

Revision ID: d5e8a2b4c6f1
Revises: c3a9f1e07b52
Create Date: 2026-10-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d5e8a2b4c6f1"
down_revision: Union[str, None] = "c3a9f1e07b52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "applications",
        sa.Column("require_access", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("applications", "require_access")
