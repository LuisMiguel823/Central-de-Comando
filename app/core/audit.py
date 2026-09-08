from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditEvent, User


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_label: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    description: str | None = None,
    request: Request | None = None,
    meta: dict | None = None,
    commit: bool = True,
) -> AuditEvent:
    """Grava um evento na trilha de auditoria."""
    ip = None
    ua = None
    if request is not None:
        ip = request.client.host if request.client else None
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            ip = fwd.split(",")[0].strip()
        ua = request.headers.get("user-agent")

    event = AuditEvent(
        actor_user_id=actor.id if actor else None,
        actor_label=actor_label if actor is None else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        description=description,
        ip_address=ip,
        user_agent=(ua or "")[:400] or None,
        meta=meta,
    )
    db.add(event)
    if commit:
        db.commit()
    return event
