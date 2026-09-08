from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuditEvent(Base):
    """Trilha de auditoria: entrou/saiu, permissão concedida/revogada, CRUD..."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_label: Mapped[str | None] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(80))
    target_id: Mapped[str | None] = mapped_column(String(80))
    description: Mapped[str | None] = mapped_column(String(500))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    meta: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True, nullable=False
    )

    actor: Mapped["User | None"] = relationship()

    @property
    def actor_name(self) -> str:
        if self.actor is not None:
            return self.actor.full_name or self.actor.username
        return self.actor_label or "sistema"
