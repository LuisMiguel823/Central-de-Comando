from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.client import Client
    from app.models.permission import UserAppPermission


class User(TimestampMixin, Base):
    """Operador / pessoa que autentica no APP CENTRAL."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))

    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    client_id: Mapped[int | None] = mapped_column(
        ForeignKey("clients.id", ondelete="SET NULL")
    )

    # Federação de identidade
    govbr_sub: Mapped[str | None] = mapped_column(String(255), unique=True)
    cpf: Mapped[str | None] = mapped_column(String(14), unique=True)
    photo_url: Mapped[str | None] = mapped_column(String(500))
    account_level: Mapped[int | None] = mapped_column()  # nível da conta no Login Único (1/2/3)

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)

    client: Mapped["Client | None"] = relationship(back_populates="operators")
    permissions: Mapped[list["UserAppPermission"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserAppPermission.user_id",
    )

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username}>"
