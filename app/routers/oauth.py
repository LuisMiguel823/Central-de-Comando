from __future__ import annotations

import base64
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import audit
from app.core.security import generate_token, jwks, utcnow, verify_password
from app.database import get_db
from app.models import Application, OAuthAuthorizationCode, OAuthToken, User
from app.services import oidc

router = APIRouter(tags=["oidc-provider"])


@router.get("/.well-known/openid-configuration")
def discovery():
    return oidc.discovery_document()


@router.get("/oauth/jwks.json")
def jwks_endpoint():
    return jwks()


def _get_app(db: Session, client_id: str) -> Application:
    app = db.scalar(
        select(Application).where(Application.oauth_client_id == client_id)
    )
    if app is None or not app.is_active:
        raise HTTPException(status_code=400, detail="client_id inválido ou inativo.")
    return app


# --------------------------------------------------------------------------- #
# /authorize  (o usuário precisa estar logado no APP CENTRAL)
# --------------------------------------------------------------------------- #
@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    db: Session = Depends(get_db),
):
    app = _get_app(db, client_id)

    if response_type != "code":
        raise HTTPException(status_code=400, detail="response_type não suportado (use 'code').")
    if redirect_uri not in app.redirect_uri_list:
        raise HTTPException(status_code=400, detail="redirect_uri não registrado para este app.")

    requested = set(scope.split())
    allowed = set(app.scope_list) | {"openid", "profile", "email"}
    if not requested.issubset(allowed):
        raise HTTPException(status_code=400, detail="scope não permitido para este app.")

    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse(
            f"/login?next={request.url.path}%3F{request.url.query}",
            status_code=status.HTTP_302_FOUND,
        )
    user = db.get(User, uid)
    if user is None or not user.is_active:
        request.session.clear()
        return RedirectResponse("/login", status_code=302)

    code = OAuthAuthorizationCode(
        code=generate_token(32),
        user_id=user.id,
        application_id=app.id,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=utcnow() + timedelta(seconds=settings.auth_code_ttl),
    )
    db.add(code)
    audit.record(
        db, "oauth.authorize", actor=user, target_type="application",
        target_id=app.id, description=f"Autorizou {app.name}", request=request,
        commit=False,
    )
    db.commit()

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code.code}"
    if state:
        from urllib.parse import quote

        location += f"&state={quote(state)}"
    return RedirectResponse(location, status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# /token
# --------------------------------------------------------------------------- #
def _client_credentials(
    request: Request, client_id: str | None, client_secret: str | None
) -> tuple[str, str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        raw = base64.b64decode(header[6:]).decode()
        cid, _, csec = raw.partition(":")
        return cid, csec
    return client_id or "", client_secret or ""


@router.post("/oauth/token")
def token(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    refresh_token: str | None = Form(None),
    code_verifier: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    scope: str | None = Form(None),
    db: Session = Depends(get_db),
):
    cid, csec = _client_credentials(request, client_id, client_secret)
    app = _get_app(db, cid)
    if app.is_confidential and not verify_password(csec, app.oauth_client_secret_hash):
        raise HTTPException(status_code=401, detail="client_secret inválido.")

    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="code ausente.")
        row = db.scalar(
            select(OAuthAuthorizationCode).where(OAuthAuthorizationCode.code == code)
        )
        if row is None or row.used or row.application_id != app.id:
            raise HTTPException(status_code=400, detail="code inválido.")
        if row.expires_at < utcnow():
            raise HTTPException(status_code=400, detail="code expirado.")
        if redirect_uri and redirect_uri != row.redirect_uri:
            raise HTTPException(status_code=400, detail="redirect_uri divergente.")
        if row.code_challenge and not oidc.verify_pkce(
            code_verifier or "", row.code_challenge, row.code_challenge_method
        ):
            raise HTTPException(status_code=400, detail="PKCE inválido.")

        row.used = True
        user = db.get(User, row.user_id)
        tokens = oidc.issue_token_set(db, user, app, row.scope, nonce=row.nonce)
        audit.record(
            db, "oauth.token", actor=user, target_type="application",
            target_id=app.id, description="Emitiu tokens (authorization_code)",
            request=request, commit=False,
        )
        db.commit()
        return JSONResponse(tokens)

    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="refresh_token ausente.")
        row = db.scalar(
            select(OAuthToken).where(OAuthToken.refresh_token == refresh_token)
        )
        if (
            row is None
            or row.revoked
            or row.application_id != app.id
            or (row.refresh_expires_at and row.refresh_expires_at < utcnow())
        ):
            raise HTTPException(status_code=400, detail="refresh_token inválido.")
        row.revoked = True
        user = db.get(User, row.user_id)
        tokens = oidc.issue_token_set(db, user, app, scope or row.scope)
        audit.record(
            db, "oauth.refresh", actor=user, target_type="application",
            target_id=app.id, description="Renovou tokens", request=request, commit=False,
        )
        db.commit()
        return JSONResponse(tokens)

    raise HTTPException(status_code=400, detail=f"grant_type não suportado: {grant_type}")


# --------------------------------------------------------------------------- #
# /userinfo
# --------------------------------------------------------------------------- #
@router.get("/oauth/userinfo")
@router.post("/oauth/userinfo")
def userinfo(request: Request, db: Session = Depends(get_db)):
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token ausente.")
    from app.core.security import decode_jwt

    try:
        payload = decode_jwt(header[7:])
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"Token inválido: {exc}") from exc

    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuário inválido.")
    app = db.scalar(
        select(Application).where(Application.oauth_client_id == payload.get("aud"))
    )
    if app is None:
        raise HTTPException(status_code=401, detail="audience desconhecida.")
    return oidc.userinfo_claims(db, user, app, payload.get("scope", "openid profile email"))


# --------------------------------------------------------------------------- #
# Tela de consentimento simples (opcional) — aqui só um atalho informativo
# --------------------------------------------------------------------------- #
@router.get("/oauth/apps")
def list_public_apps(db: Session = Depends(get_db)):
    apps = db.scalars(select(Application).where(Application.is_active.is_(True))).all()
    return [
        {"name": a.name, "slug": a.slug, "client_id": a.oauth_client_id, "base_url": a.base_url}
        for a in apps
    ]
