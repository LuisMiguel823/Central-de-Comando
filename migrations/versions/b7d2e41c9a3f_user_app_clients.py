"""user_app_clients: cliente do usuario POR sistema

Revision ID: b7d2e41c9a3f
Revises: a1f3c9d20b7e
Create Date: 2026-09-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b7d2e41c9a3f"
down_revision: Union[str, None] = "a1f3c9d20b7e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_app_clients",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("application_id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(now())"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(now())"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "application_id", name="uq_user_app_client"),
    )
    # Mantém o que já funciona: quem tem cliente no cadastro geral e já tem
    # permissão num sistema ganha o vínculo desse sistema com o mesmo cliente.
    op.execute(
        """
        INSERT INTO user_app_clients (user_id, application_id, client_id)
        SELECT DISTINCT u.id, p.application_id, u.client_id
        FROM users u
        JOIN user_app_permissions p ON p.user_id = u.id
        WHERE u.client_id IS NOT NULL
        """
    )


def downgrade() -> None:
    op.drop_table("user_app_clients")
