from __future__ import annotations

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin


class UserAppClient(TimestampMixin, Base):
    """Cliente (ex.: prefeitura/instituto) de um usuário DENTRO de um sistema.

    É a configuração do usuário naquele sistema — o que vira o claim
    `client_code` no token daquele app. Vale só pro sistema em questão; o
    `User.client_id` (cadastro geral da Central) é só o valor padrão quando
    não existe vínculo específico.
    """

    __tablename__ = "user_app_clients"
    __table_args__ = (UniqueConstraint("user_id", "application_id", name="uq_user_app_client"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )

    client = relationship("Client")
