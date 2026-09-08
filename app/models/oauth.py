from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.mixins import TimestampMixin


class OAuthAuthorizationCode(TimestampMixin, Base):
    """Código de autorização de curta duração (fluxo authorization_code)."""

    __tablename__ = "oauth_authorization_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    nonce: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str | None] = mapped_column(String(500))
    code_challenge: Mapped[str | None] = mapped_column(String(255))
    code_challenge_method: Mapped[str | None] = mapped_column(String(10))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class OAuthToken(TimestampMixin, Base):
    """Rastro dos tokens emitidos (access via JWT stateless; refresh persistido)."""

    __tablename__ = "oauth_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    access_token_jti: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    refresh_token: Mapped[str | None] = mapped_column(String(128), unique=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    scope: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    refresh_expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
