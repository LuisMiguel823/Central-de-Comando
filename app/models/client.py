from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.application import Application
    from app.models.user import User


class ClientTier(str, enum.Enum):
    BRONZE = "BRONZE"
    PRATA = "PRATA"
    OURO = "OURO"
    DIAMANTE = "DIAMANTE"


class Client(TimestampMixin, Base):
    """Cliente / contratante do serviço (ex.: uma Câmara Municipal)."""

    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    city: Mapped[str | None] = mapped_column(String(120))
    tier: Mapped[ClientTier] = mapped_column(
        Enum(ClientTier), default=ClientTier.BRONZE, nullable=False
    )
    contact_name: Mapped[str | None] = mapped_column(String(200))
    contact_email: Mapped[str | None] = mapped_column(String(254))
    contact_phone: Mapped[str | None] = mapped_column(String(40))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Instância do Login Único municipal desta câmara (sobrescreve o global do .env)
    loginunico_base_url: Mapped[str | None] = mapped_column(String(300))
    loginunico_sys: Mapped[str | None] = mapped_column(String(40))

    applications: Mapped[list["Application"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )
    operators: Mapped[list["User"]] = relationship(back_populates="client")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Client {self.code}>"
