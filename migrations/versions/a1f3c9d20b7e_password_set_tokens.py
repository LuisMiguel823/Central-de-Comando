"""password_set_tokens: links de uso único pra definir senha

Revision ID: a1f3c9d20b7e
Revises: 8c48522765aa
Create Date: 2026-09-24
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a1f3c9d20b7e"
down_revision: Union[str, None] = "8c48522765aa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "password_set_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(now())"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(now())"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_password_set_tokens_user_id", "password_set_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_password_set_tokens_user_id", table_name="password_set_tokens")
    op.drop_table("password_set_tokens")
