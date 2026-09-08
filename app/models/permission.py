from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.application import Application
    from app.models.user import User


class Permission(TimestampMixin, Base):
    """Item do catálogo de permissões de um app (ex.: 'clientes.editar')."""

    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("application_id", "code", name="uq_perm_app_code"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))

    application: Mapped["Application"] = relationship(back_populates="permissions")
    assignments: Mapped[list["UserAppPermission"]] = relationship(
        back_populates="permission", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Permission {self.code}>"


class UserAppPermission(TimestampMixin, Base):
    """Concessão de uma permissão a um operador."""

    __tablename__ = "user_app_permissions"
    __table_args__ = (
        UniqueConstraint("user_id", "permission_id", name="uq_user_permission"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )
    granted_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)

    user: Mapped["User"] = relationship(
        back_populates="permissions", foreign_keys=[user_id]
    )
    granted_by: Mapped["User | None"] = relationship(foreign_keys=[granted_by_id])
    application: Mapped["Application"] = relationship(back_populates="assignments")
    permission: Mapped["Permission"] = relationship(back_populates="assignments")
