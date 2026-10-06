from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.deps import get_api_user, require_api_admin
from app.core.security import decode_jwt, utcnow, verify_password
from app.database import get_db
from app.models import Application, Client, OAuthToken, Permission, User, UserAppPermission
from app.services.permissions import grant as grant_permission
from app.services.permissions import permissions_for

router = APIRouter(prefix="/api/v1", tags=["api"])


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class MeOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_superuser: bool
    client_id: int | None
    client_code: str | None


class ClientOut(BaseModel):
    id: int
    name: str
    code: str
    city: str | None
    tier: str
    is_active: bool


class AppOut(BaseModel):
    id: int
    name: str
    slug: str
    client_id: int | None
    oauth_client_id: str
    is_active: bool


class OperatorOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    is_superuser: bool
    client_id: int | None


# --------------------------------------------------------------------------- #
# Identidade do portador do token
# --------------------------------------------------------------------------- #
@router.get("/me", response_model=MeOut)
def me(user: User = Depends(get_api_user)):
    return MeOut(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_superuser=user.is_superuser,
        client_id=user.client_id,
        client_code=user.client.code if user.client else None,
    )


@router.get("/apps/{slug}/my-permissions")
def my_permissions(
    slug: str,
    user: User = Depends(get_api_user),
    db: Session = Depends(get_db),
):
    """Usado por um app satélite para saber o que o portador do token pode fazer."""
    app = db.scalar(select(Application).where(Application.slug == slug))
    if app is None:
        raise HTTPException(status_code=404, detail="App não encontrado.")
    return {
        "app": app.slug,
        "user_id": user.id,
        "username": user.username,
        "permissions": permissions_for(db, user, app),
        "is_superuser": user.is_superuser,
    }


# --------------------------------------------------------------------------- #
# Introspecção de token (RFC 7662) — o app satélite se autentica com client_id/secret
# --------------------------------------------------------------------------- #
@router.post("/introspect")
def introspect(
    request: Request,
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(""),
    db: Session = Depends(get_db),
):
    app = db.scalar(select(Application).where(Application.oauth_client_id == client_id))
    if app is None or (
        app.is_confidential
        and not verify_password(client_secret, app.oauth_client_secret_hash)
    ):
        raise HTTPException(status_code=401, detail="client inválido.")

    try:
        payload = decode_jwt(token, audience=app.oauth_client_id)
    except Exception:  # noqa: BLE001
        return {"active": False}

    row = db.scalar(select(OAuthToken).where(OAuthToken.access_token_jti == payload["jti"]))
    if row is not None and (row.revoked or row.expires_at < utcnow()):
        return {"active": False}

    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        return {"active": False}

    return {
        "active": True,
        "sub": payload["sub"],
        "username": user.username,
        "email": user.email,
        "scope": payload.get("scope", ""),
        "client_id": app.oauth_client_id,
        "exp": payload["exp"],
        "iat": payload["iat"],
        "permissions": permissions_for(db, user, app),
        "is_superuser": user.is_superuser,
    }


# --------------------------------------------------------------------------- #
# Auto-cadastro do catálogo de permissões — o próprio app satélite (ou a IA do
# dono dele) manda a lista levantada no código, autenticando com client_id/secret.
# Só cria/atualiza: NUNCA apaga, pra um sync errado não revogar acesso em produção.
# --------------------------------------------------------------------------- #
_PERM_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{0,99}$")
_MAX_SYNC_PERMISSIONS = 300


class PermissionIn(BaseModel):
    code: str
    name: str | None = None
    description: str | None = None


class PermissionSyncIn(BaseModel):
    client_id: str
    client_secret: str
    permissions: list[PermissionIn]


@router.post("/apps/permissions/sync")
def sync_permissions(
    body: PermissionSyncIn,
    request: Request,
    db: Session = Depends(get_db),
):
    app = db.scalar(select(Application).where(Application.oauth_client_id == body.client_id))
    if (
        app is None
        or not app.is_active
        or not verify_password(body.client_secret, app.oauth_client_secret_hash)
    ):
        raise HTTPException(status_code=401, detail="client inválido.")
    if len(body.permissions) > _MAX_SYNC_PERMISSIONS:
        raise HTTPException(
            status_code=400, detail=f"Máximo de {_MAX_SYNC_PERMISSIONS} permissões por chamada."
        )

    wanted: dict[str, PermissionIn] = {}
    for item in body.permissions:
        code = item.code.strip().lower()
        if not _PERM_CODE_RE.match(code):
            raise HTTPException(
                status_code=400,
                detail=f"code inválido: '{item.code}'. Use minúsculas, números, '.', '_' ou '-' (ex.: contratos.assinar).",
            )
        wanted[code] = item

    existing = {p.code: p for p in app.permissions}
    created = updated = 0
    for code, item in wanted.items():
        name = (item.name or "").strip()[:200] or code
        description = (item.description or "").strip()[:500] or None
        current = existing.get(code)
        if current is None:
            db.add(Permission(application_id=app.id, code=code, name=name, description=description))
            created += 1
        elif current.name != name or current.description != description:
            current.name = name
            current.description = description
            updated += 1

    if created or updated:
        audit.record(
            db, "permission.sync_api", actor_label=f"app:{app.slug}", target_type="application",
            target_id=app.id,
            description=f"Sistema {app.slug} cadastrou permissões via API: +{created} / ~{updated}",
            request=request, meta={"created": created, "updated": updated}, commit=False,
        )
    db.commit()
    return {
        "app": app.slug,
        "created": created,
        "updated": updated,
        "unchanged": len(wanted) - created - updated,
        "total_in_catalog": len(existing) + created,
    }


# --------------------------------------------------------------------------- #
# Importação de acessos — o sistema satélite manda quem tem qual permissão hoje
# (ex.: antigos is_staff). Quem ainda não existe na Central é criado sem senha e
# entra pelo login federado (casa por e-mail). Só concede: NUNCA revoga.
# --------------------------------------------------------------------------- #
_MAX_SYNC_USERS = 1000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AccessUserIn(BaseModel):
    email: str
    full_name: str | None = None
    permissions: list[str]


class AccessSyncIn(BaseModel):
    client_id: str
    client_secret: str
    users: list[AccessUserIn]


@router.post("/apps/access/sync")
def sync_access(
    body: AccessSyncIn,
    request: Request,
    db: Session = Depends(get_db),
):
    app = db.scalar(select(Application).where(Application.oauth_client_id == body.client_id))
    if (
        app is None
        or not app.is_active
        or not verify_password(body.client_secret, app.oauth_client_secret_hash)
    ):
        raise HTTPException(status_code=401, detail="client inválido.")
    if len(body.users) > _MAX_SYNC_USERS:
        raise HTTPException(
            status_code=400, detail=f"Máximo de {_MAX_SYNC_USERS} usuários por chamada."
        )

    catalog = {p.code: p for p in app.permissions}
    users_created = grants_added = 0
    skipped: list[str] = []

    for item in body.users:
        email = item.email.strip().lower()
        if not _EMAIL_RE.match(email) or len(email) > 254:
            skipped.append(item.email)
            continue
        codes = {c.strip().lower() for c in item.permissions}
        for code in codes:
            if not _PERM_CODE_RE.match(code):
                raise HTTPException(status_code=400, detail=f"code inválido: '{code}'.")

        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            base = email.split("@")[0][:48] or "usuario"
            username, i = base, 1
            while db.scalar(select(User).where(User.username == username)):
                username = f"{base}{i}"
                i += 1
            user = User(
                username=username,
                email=email,
                full_name=(item.full_name or "").strip()[:200] or base,
                password_hash=None,
                is_active=True,
            )
            db.add(user)
            db.flush()
            users_created += 1

        for code in sorted(codes):
            perm = catalog.get(code)
            if perm is None:
                perm = Permission(application_id=app.id, code=code, name=code)
                db.add(perm)
                db.flush()
                catalog[code] = perm
            before = db.scalar(
                select(UserAppPermission.id).where(
                    UserAppPermission.user_id == user.id,
                    UserAppPermission.permission_id == perm.id,
                )
            )
            if before is None:
                grant_permission(db, user=user, permission=perm, granted_by=None)
                grants_added += 1

    audit.record(
        db, "permission.access_sync_api", actor_label=f"app:{app.slug}",
        target_type="application", target_id=app.id,
        description=f"Sistema {app.slug} importou acessos via API: {users_created} usuário(s) novo(s), +{grants_added} concessão(ões)",
        request=request,
        meta={"users_created": users_created, "grants_added": grants_added, "skipped": skipped},
        commit=False,
    )
    db.commit()
    return {
        "app": app.slug,
        "users_received": len(body.users),
        "users_created": users_created,
        "grants_added": grants_added,
        "skipped_invalid_email": skipped,
    }


# --------------------------------------------------------------------------- #
# Leitura administrativa
# --------------------------------------------------------------------------- #
@router.get("/clients", response_model=list[ClientOut])
def api_clients(db: Session = Depends(get_db), _: User = Depends(require_api_admin)):
    return [
        ClientOut(
            id=c.id, name=c.name, code=c.code, city=c.city,
            tier=c.tier.value, is_active=c.is_active,
        )
        for c in db.scalars(select(Client).order_by(Client.name)).all()
    ]


@router.get("/apps", response_model=list[AppOut])
def api_apps(db: Session = Depends(get_db), _: User = Depends(require_api_admin)):
    return [
        AppOut(
            id=a.id, name=a.name, slug=a.slug, client_id=a.client_id,
            oauth_client_id=a.oauth_client_id, is_active=a.is_active,
        )
        for a in db.scalars(select(Application).order_by(Application.name)).all()
    ]


@router.get("/operators", response_model=list[OperatorOut])
def api_operators(db: Session = Depends(get_db), _: User = Depends(require_api_admin)):
    return [
        OperatorOut(
            id=u.id, username=u.username, email=u.email, full_name=u.full_name,
            is_active=u.is_active, is_superuser=u.is_superuser, client_id=u.client_id,
        )
        for u in db.scalars(select(User).order_by(User.full_name)).all()
    ]
