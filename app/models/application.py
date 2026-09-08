from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.client import Client
    from app.models.permission import Permission, UserAppPermission


class Application(TimestampMixin, Base):
    """App satélite (APP 1, APP 2, APP 3...). Também é um client OAuth/OIDC."""

    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    base_url: Mapped[str | None] = mapped_column(String(500))

    client_id: Mapped[int | None] = mapped_column(
        ForeignKey("clients.id", ondelete="SET NULL")
    )

    # Credenciais OAuth
    oauth_client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    oauth_client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uris: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_scopes: Mapped[str] = mapped_column(
        String(500), default="openid profile email", nullable=False
    )
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    client: Mapped["Client | None"] = relationship(back_populates="applications")
    permissions: Mapped[list["Permission"]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )
    assignments: Mapped[list["UserAppPermission"]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )

    @property
    def redirect_uri_list(self) -> list[str]:
        return [u.strip() for u in self.redirect_uris.replace(",", "\n").splitlines() if u.strip()]

    @property
    def scope_list(self) -> list[str]:
        return [s for s in self.allowed_scopes.split() if s]

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Application {self.slug}>"
