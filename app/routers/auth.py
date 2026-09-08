from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import audit
from app.core.security import utcnow, verify_password
from app.core.templating import render
from app.database import get_db
from app.models import Client, User
from app.services import govbr, loginunico, microsoft

router = APIRouter(tags=["auth"])


def _login_user(request: Request, user: User) -> None:
    request.session["uid"] = user.id
    request.session["name"] = user.full_name


def _safe_next(raw: str | None) -> str:
    if raw and raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/"


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", error: str | None = None):
    if request.session.get("uid"):
        return RedirectResponse(_safe_next(next), status_code=status.HTTP_302_FOUND)
    return render(
        request,
        "login.html",
        {
            "next": next,
            "error": error,
            "govbr_configured": govbr.is_configured(),
            "loginunico_configured": loginunico.is_configured(),
            "microsoft_configured": microsoft.is_configured(),
        },
    )


@router.post("/login")
def login_submit(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    user = db.scalar(
        select(User).where(
            or_(User.username == identifier.strip(), User.email == identifier.strip().lower())
        )
    )
    if user is None or not verify_password(password, user.password_hash):
        audit.record(
            db,
            "auth.login_failed",
            actor_label=identifier[:180],
            description="Credenciais inválidas",
            request=request,
        )
        return render(
            request,
            "login.html",
            {
                "next": next,
                "error": "Usuário ou senha incorretos.",
                "govbr_configured": govbr.is_configured(),
                "loginunico_configured": loginunico.is_configured(),
                "microsoft_configured": microsoft.is_configured(),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        return render(
            request,
            "login.html",
            {
                "next": next,
                "error": "Conta aguardando liberação de um administrador.",
                "govbr_configured": govbr.is_configured(),
                "loginunico_configured": loginunico.is_configured(),
                "microsoft_configured": microsoft.is_configured(),
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    user.last_login_at = utcnow()
    _login_user(request, user)
    audit.record(db, "auth.login", actor=user, description="Login local", request=request)
    return RedirectResponse(_safe_next(next), status_code=status.HTTP_302_FOUND)


@router.get("/logout")
@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    uid = request.session.get("uid")
    if uid:
        user = db.get(User, uid)
        audit.record(db, "auth.logout", actor=user, description="Logout", request=request)
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# Federação gov.br
# --------------------------------------------------------------------------- #
@router.get("/auth/govbr/login")
async def govbr_login(request: Request, next: str = "/"):
    if not govbr.is_configured():
        return RedirectResponse(
            "/login?error=Login+gov.br+n%C3%A3o+configurado", status_code=302
        )
    request.session["govbr_next"] = _safe_next(next)
    return await govbr.oauth.govbr.authorize_redirect(
        request, settings.govbr_redirect_uri
    )


@router.get("/auth/govbr/callback")
async def govbr_callback(request: Request, db: Session = Depends(get_db)):
    if not govbr.is_configured():
        return RedirectResponse("/login", status_code=302)

    try:
        token = await govbr.oauth.govbr.authorize_access_token(request)
    except Exception as exc:  # noqa: BLE001
        audit.record(
            db, "auth.govbr_failed", actor_label="gov.br",
            description=f"Falha na troca de token: {exc}", request=request,
        )
        return RedirectResponse(
            "/login?error=Falha+na+autentica%C3%A7%C3%A3o+gov.br", status_code=302
        )

    info = token.get("userinfo") or await govbr.fetch_userinfo(token)
    sub = str(info.get("sub") or info.get("preferred_username") or "").strip()
    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or info.get("preferred_username") or email or f"gov.br {sub}"

    if not sub:
        return RedirectResponse(
            "/login?error=gov.br+n%C3%A3o+retornou+identificador", status_code=302
        )

    user = db.scalar(select(User).where(User.govbr_sub == sub))
    if user is None and email:
        user = db.scalar(select(User).where(User.email == email))
        if user is not None:
            user.govbr_sub = sub

    created = False
    if user is None:
        if not settings.govbr_auto_provision:
            return RedirectResponse(
                "/login?error=Usu%C3%A1rio+gov.br+sem+cadastro", status_code=302
            )
        base_username = (email.split("@")[0] if email else f"govbr_{sub}")[:48]
        username = base_username
        i = 1
        while db.scalar(select(User).where(User.username == username)):
            username = f"{base_username}{i}"
            i += 1
        user = User(
            username=username,
            email=email or f"{sub}@govbr.local",
            full_name=name,
            govbr_sub=sub,
            cpf=sub if sub.isdigit() and len(sub) == 11 else None,
            is_active=settings.govbr_provision_active,
            password_hash=None,
        )
        db.add(user)
        db.flush()
        created = True

    audit.record(
        db,
        "auth.govbr_provision" if created else "auth.login",
        actor=user,
        description="Novo operador via gov.br" if created else "Login via gov.br",
        request=request,
        meta={"sub": sub, "email": email},
        commit=False,
    )

    if not user.is_active:
        db.commit()
        return RedirectResponse(
            "/login?error=Conta+criada.+Aguarde+libera%C3%A7%C3%A3o.", status_code=302
        )

    user.last_login_at = utcnow()
    _login_user(request, user)
    db.commit()
    nxt = request.session.pop("govbr_next", "/")
    return RedirectResponse(_safe_next(nxt), status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# Federação Login Único municipal (Neomind Fusion WSAuth)
# --------------------------------------------------------------------------- #
@router.get("/auth/loginunico/login")
def loginunico_login(
    request: Request,
    next: str = "/",
    cliente: str | None = None,
    db: Session = Depends(get_db),
):
    if not loginunico.is_configured():
        return RedirectResponse(
            "/login?error=Login+%C3%9Anico+n%C3%A3o+configurado", status_code=302
        )

    client = None
    if cliente:
        client = db.scalar(select(Client).where(Client.code == cliente.strip().upper()))

    instance = loginunico.resolve_instance(client)
    try:
        data = loginunico.init_auth(instance, settings.loginunico_callback_url)
    except Exception as exc:  # noqa: BLE001
        audit.record(
            db, "auth.loginunico_failed", actor_label="login-unico",
            description=f"WSAuthInit falhou: {exc}", request=request,
        )
        return RedirectResponse(
            "/login?error=Falha+ao+iniciar+o+Login+%C3%9Anico", status_code=302
        )

    request.session["lu_token"] = data["token"]
    request.session["lu_base_url"] = instance.base_url
    request.session["lu_sys"] = instance.sys
    request.session["lu_client_id"] = client.id if client else None
    request.session["lu_next"] = _safe_next(next)
    request.session.pop("lu_verified", None)
    return RedirectResponse(data["location"], status_code=status.HTTP_302_FOUND)


@router.get("/auth/loginunico/callback")
def loginunico_callback(request: Request, db: Session = Depends(get_db)):
    token = request.session.get("lu_token")
    base_url = request.session.get("lu_base_url")
    if not token or not base_url:
        return RedirectResponse(
            "/login?error=Sess%C3%A3o+do+Login+%C3%9Anico+expirada", status_code=302
        )
    if request.session.get("lu_verified"):
        # o WSAuthVerify só pode ser consultado uma vez por token
        return RedirectResponse("/login", status_code=302)
    request.session["lu_verified"] = True

    instance = loginunico.Instance(base_url=base_url, sys=request.session.get("lu_sys", settings.loginunico_sys))
    try:
        info = loginunico.verify_auth(instance, token)
    except Exception as exc:  # noqa: BLE001
        audit.record(
            db, "auth.loginunico_failed", actor_label="login-unico",
            description=f"WSAuthVerify falhou: {exc}", request=request,
        )
        return RedirectResponse(
            "/login?error=Falha+ao+verificar+o+Login+%C3%9Anico", status_code=302
        )

    if not info["ok"]:
        audit.record(
            db, "auth.loginunico_failed", actor_label="login-unico",
            description="WSAuthVerify sem dados de usuário", request=request,
            meta={"raw": info.get("raw")},
        )
        return RedirectResponse(
            "/login?error=Login+%C3%9Anico+n%C3%A3o+retornou+dados", status_code=302
        )

    level = info.get("account_level")
    if level is not None and level < settings.loginunico_min_level:
        audit.record(
            db, "auth.loginunico_denied", actor_label=info.get("name") or "login-unico",
            description=f"Nível da conta {level} < mínimo {settings.loginunico_min_level}",
            request=request, meta={"cpf": info.get("cpf")},
        )
        return RedirectResponse(
            "/login?error=N%C3%ADvel+da+conta+insuficiente", status_code=302
        )

    cpf = info.get("cpf")
    email = info.get("email")
    name = info.get("name") or email or (f"CPF {cpf}" if cpf else "Usuário Login Único")

    user = None
    if cpf:
        user = db.scalar(select(User).where(User.cpf == cpf))
    if user is None and email:
        user = db.scalar(select(User).where(User.email == email))
        if user is not None and cpf and not user.cpf:
            user.cpf = cpf

    created = False
    if user is None:
        if not settings.loginunico_auto_provision:
            return RedirectResponse(
                "/login?error=Usu%C3%A1rio+sem+cadastro+no+APP+CENTRAL", status_code=302
            )
        base = (email.split("@")[0] if email else (cpf or "lu_user"))[:48]
        username = base
        i = 1
        while db.scalar(select(User).where(User.username == username)):
            username = f"{base}{i}"
            i += 1
        user = User(
            username=username,
            email=email or (f"{cpf}@loginunico.local" if cpf else f"{username}@loginunico.local"),
            full_name=name,
            cpf=cpf,
            is_active=settings.loginunico_provision_active,
            password_hash=None,
        )
        lu_client_id = request.session.get("lu_client_id")
        if lu_client_id:
            user.client_id = lu_client_id
        db.add(user)
        db.flush()
        created = True

    user.photo_url = info.get("photo_url") or user.photo_url
    user.account_level = level if level is not None else user.account_level

    audit.record(
        db,
        "auth.loginunico_provision" if created else "auth.login",
        actor=user,
        description="Novo operador via Login Único" if created else "Login via Login Único",
        request=request,
        meta={"cpf": cpf, "level": level, "instance": base_url},
        commit=False,
    )

    for k in ("lu_token", "lu_base_url", "lu_sys", "lu_client_id", "lu_verified"):
        request.session.pop(k, None)

    if not user.is_active:
        db.commit()
        return RedirectResponse(
            "/login?error=Conta+criada.+Aguarde+libera%C3%A7%C3%A3o.", status_code=302
        )

    user.last_login_at = utcnow()
    _login_user(request, user)
    db.commit()
    nxt = request.session.pop("lu_next", "/")
    return RedirectResponse(_safe_next(nxt), status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# SSO Microsoft (Entra ID) — Authorization Code, sem lib de OAuth
# Só autentica quem JÁ existe no APP CENTRAL (casado por e-mail).
# --------------------------------------------------------------------------- #
@router.get("/auth/microsoft/login")
def microsoft_login(request: Request, next: str = "/"):
    if not microsoft.is_configured():
        return RedirectResponse(
            "/login?error=SSO+Microsoft+n%C3%A3o+configurado", status_code=302
        )
    state = secrets.token_urlsafe(32)
    request.session["ms_state"] = state
    request.session["ms_next"] = _safe_next(next)
    return RedirectResponse(
        microsoft.authorize_url(state), status_code=status.HTTP_302_FOUND
    )


@router.get("/auth/microsoft/callback")
def microsoft_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if not microsoft.is_configured():
        return RedirectResponse("/login", status_code=302)

    expected = request.session.pop("ms_state", None)
    nxt = request.session.pop("ms_next", "/")

    if error:
        audit.record(
            db, "auth.microsoft_failed", actor_label="microsoft",
            description=f"{error}: {error_description or ''}"[:480], request=request,
        )
        return RedirectResponse(
            "/login?error=Falha+na+autentica%C3%A7%C3%A3o+Microsoft", status_code=302
        )

    if not code or not state or not expected or not secrets.compare_digest(state, expected):
        audit.record(
            db, "auth.microsoft_failed", actor_label="microsoft",
            description="state inválido ou ausente (possível CSRF)", request=request,
        )
        return RedirectResponse(
            "/login?error=Requisi%C3%A7%C3%A3o+Microsoft+inv%C3%A1lida", status_code=302
        )

    try:
        token = microsoft.exchange_code(code)
        me = microsoft.get_me(token["access_token"])
    except Exception as exc:  # noqa: BLE001
        audit.record(
            db, "auth.microsoft_failed", actor_label="microsoft",
            description=f"Troca de code/Graph falhou: {exc}"[:480], request=request,
        )
        return RedirectResponse(
            "/login?error=Falha+ao+consultar+a+Microsoft", status_code=302
        )

    email = microsoft.email_from_me(me)
    if not email:
        return RedirectResponse(
            "/login?error=Microsoft+n%C3%A3o+retornou+e-mail", status_code=302
        )

    # NÃO cria usuário: só autentica quem já existe.
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        audit.record(
            db, "auth.microsoft_denied", actor_label=email,
            description="E-mail Microsoft sem cadastro no APP CENTRAL",
            request=request, meta={"email": email},
        )
        return RedirectResponse(
            "/login?error=E-mail+Microsoft+sem+cadastro+no+APP+CENTRAL", status_code=302
        )

    if not user.is_active:
        audit.record(
            db, "auth.microsoft_denied", actor=user,
            description="Operador inativo", request=request,
        )
        return RedirectResponse(
            "/login?error=Conta+aguardando+libera%C3%A7%C3%A3o", status_code=302
        )

    user.last_login_at = utcnow()
    _login_user(request, user)
    audit.record(
        db, "auth.login", actor=user, description="Login via Microsoft (SSO)",
        request=request, meta={"email": email}, commit=False,
    )
    db.commit()
    return RedirectResponse(_safe_next(nxt), status_code=status.HTTP_302_FOUND)
