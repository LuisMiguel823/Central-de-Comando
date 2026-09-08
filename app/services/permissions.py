from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models import Application, Permission, User, UserAppPermission


def permissions_for(db: Session, user: User, app: Application) -> list[str]:
    """Códigos de permissão que o operador possui no app informado."""
    if user.is_superuser:
        rows = db.scalars(
            select(Permission.code).where(Permission.application_id == app.id)
        ).all()
        return sorted(rows)

    now = utcnow()
    stmt = (
        select(Permission.code)
        .join(UserAppPermission, UserAppPermission.permission_id == Permission.id)
        .where(
            UserAppPermission.user_id == user.id,
            UserAppPermission.application_id == app.id,
        )
        .where(
            (UserAppPermission.expires_at.is_(None))
            | (UserAppPermission.expires_at > now)
        )
    )
    return sorted(db.scalars(stmt).all())


def grant(
    db: Session,
    *,
    user: User,
    permission: Permission,
    granted_by: User | None,
) -> UserAppPermission:
    existing = db.scalar(
        select(UserAppPermission).where(
            UserAppPermission.user_id == user.id,
            UserAppPermission.permission_id == permission.id,
        )
    )
    if existing:
        return existing
    assignment = UserAppPermission(
        user_id=user.id,
        application_id=permission.application_id,
        permission_id=permission.id,
        granted_by_id=granted_by.id if granted_by else None,
    )
    db.add(assignment)
    db.flush()
    return assignment


def revoke(db: Session, *, user: User, permission: Permission) -> bool:
    existing = db.scalar(
        select(UserAppPermission).where(
            UserAppPermission.user_id == user.id,
            UserAppPermission.permission_id == permission.id,
        )
    )
    if not existing:
        return False
    db.delete(existing)
    db.flush()
    return True
