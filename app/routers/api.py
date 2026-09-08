from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_api_user, require_api_admin
from app.core.security import decode_jwt, utcnow, verify_password
from app.database import get_db
from app.models import Application, Client, OAuthToken, User
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
