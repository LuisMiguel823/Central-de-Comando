from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.deps import require_web_admin, require_web_user
from app.core.security import (
    generate_client_id,
    generate_client_secret,
    hash_password,
    utcnow,
)
from app.core.templating import render
from app.database import get_db
from app.models import (
    Application,
    AuditEvent,
    Client,
    ClientTier,
    Permission,
    User,
    UserAppPermission,
)
from app.services import permissions as perm_service

router = APIRouter(include_in_schema=False)


def _back(request: Request, fallback: str) -> str:
    ref = request.headers.get("referer")
    return ref or fallback


# --------------------------------------------------------------------------- #
# Sobre — explicação didática do que o sistema já faz
# --------------------------------------------------------------------------- #
@router.get("/sobre")
def about_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    federations = [
        {
            "name": "gov.br",
            "kind": "OIDC padrão (Authorization Code)",
            "status": "aguardando credencial",
            "tone": "amber",
            "detail": "Falta client_id/secret do gov.br e o redirect homologado.",
        },
        {
            "name": "Login Único municipal",
            "kind": "Neomind Fusion — WSAuthInit / WSAuthVerify",
            "status": "ligado (Cabo Frio)",
            "tone": "emerald",
            "detail": "Passo 1 já responde no servidor real; falta a prefeitura liberar o redirect de callback.",
        },
        {
            "name": "Microsoft (Entra ID)",
            "kind": "OAuth2 Authorization Code, sem lib",
            "status": "aguardando App Registration",
            "tone": "amber",
            "detail": "Falta criar o App Registration no Azure e preencher client_id/secret/tenant.",
        },
    ]
    return render(request, "about.html", {"user": user, "federations": federations})


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
@router.get("/")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = utcnow() - timedelta(days=7)

    kpis = [
        {
            "label": "Clientes ativos",
            "value": db.scalar(select(func.count(Client.id)).where(Client.is_active.is_(True))),
            "hover": "hover:border-cyan-400",
            "icon": "building",
        },
        {
            "label": "Operadores ativos",
            "value": db.scalar(select(func.count(User.id)).where(User.is_active.is_(True))),
            "hover": "hover:border-emerald-400",
            "icon": "users",
        },
        {
            "label": "Aplicações",
            "value": db.scalar(select(func.count(Application.id)).where(Application.is_active.is_(True))),
            "hover": "hover:border-violet-400",
            "icon": "grid",
        },
        {
            "label": "Permissões concedidas",
            "value": db.scalar(select(func.count(UserAppPermission.id))),
            "hover": "hover:border-teal-400",
            "icon": "key",
        },
        {
            "label": "Logins hoje",
            "value": db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "auth.login", AuditEvent.created_at >= today
                )
            ),
            "hover": "hover:border-amber-400",
            "icon": "login",
        },
        {
            "label": "Logins com falha (7d)",
            "value": db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "auth.login_failed",
                    AuditEvent.created_at >= week_ago,
                )
            ),
            "hover": "hover:border-red-400",
            "icon": "alert",
        },
        {
            "label": "Operadores pendentes",
            "value": db.scalar(select(func.count(User.id)).where(User.is_active.is_(False))),
            "hover": "hover:border-orange-400",
            "icon": "clock",
        },
        {
            "label": "Eventos (24h)",
            "value": db.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.created_at >= utcnow() - timedelta(hours=24)
                )
            ),
            "hover": "hover:border-blue-400",
            "icon": "activity",
        },
    ]

    recent = db.scalars(
        select(AuditEvent)
        .options(selectinload(AuditEvent.actor))
        .order_by(AuditEvent.created_at.desc())
        .limit(12)
    ).all()

    by_tier = dict(
        db.execute(
            select(Client.tier, func.count(Client.id)).group_by(Client.tier)
        ).all()
    )
    tiers = [
        {"name": t.value, "count": by_tier.get(t, 0)} for t in ClientTier
    ]

    return render(
        request,
        "dashboard.html",
        {"user": user, "kpis": kpis, "recent": recent, "tiers": tiers},
    )


# --------------------------------------------------------------------------- #
# Clientes
# --------------------------------------------------------------------------- #
@router.get("/clientes")
def clients_list(
    request: Request,
    q: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    stmt = select(Client).order_by(Client.name)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where((Client.name.like(like)) | (Client.code.like(like)))
    clients = db.scalars(stmt).all()
    counts = dict(
        db.execute(
            select(Application.client_id, func.count(Application.id)).group_by(
                Application.client_id
            )
        ).all()
    )
    return render(
        request,
        "clients/list.html",
        {"user": user, "clients": clients, "q": q or "", "app_counts": counts,
         "tiers": [t.value for t in ClientTier]},
    )


@router.post("/clientes")
def clients_create(
    request: Request,
    name: str = Form(...),
    code: str = Form(...),
    city: str = Form(""),
    tier: str = Form("BRONZE"),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    loginunico_base_url: str = Form(""),
    loginunico_sys: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    code = code.strip().upper()
    if db.scalar(select(Client).where(Client.code == code)):
        raise HTTPException(status_code=400, detail=f"Já existe cliente com código {code}.")
    client = Client(
        name=name.strip(),
        code=code,
        city=city.strip() or None,
        tier=ClientTier(tier),
        contact_name=contact_name.strip() or None,
        contact_email=contact_email.strip().lower() or None,
        contact_phone=contact_phone.strip() or None,
        loginunico_base_url=loginunico_base_url.strip() or None,
        loginunico_sys=loginunico_sys.strip() or None,
    )
    db.add(client)
    db.flush()
    audit.record(db, "client.create", actor=user, target_type="client", target_id=client.id,
                 description=f"Criou cliente {client.code}", request=request, commit=False)
    db.commit()
    return RedirectResponse("/clientes", status_code=status.HTTP_302_FOUND)


@router.post("/clientes/{client_id}/editar")
def clients_update(
    client_id: int,
    request: Request,
    name: str = Form(...),
    city: str = Form(""),
    tier: str = Form("BRONZE"),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    loginunico_base_url: str = Form(""),
    loginunico_sys: str = Form(""),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    client = db.get(Client, client_id) or _404("Cliente")
    client.name = name.strip()
    client.city = city.strip() or None
    client.tier = ClientTier(tier)
    client.contact_name = contact_name.strip() or None
    client.contact_email = contact_email.strip().lower() or None
    client.contact_phone = contact_phone.strip() or None
    client.loginunico_base_url = loginunico_base_url.strip() or None
    client.loginunico_sys = loginunico_sys.strip() or None
    client.is_active = is_active == "on"
    audit.record(db, "client.update", actor=user, target_type="client", target_id=client.id,
                 description=f"Editou cliente {client.code}", request=request, commit=False)
    db.commit()
    return RedirectResponse("/clientes", status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# Operadores
# --------------------------------------------------------------------------- #
@router.get("/operadores")
def operators_list(
    request: Request,
    q: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    stmt = (
        select(User)
        .options(selectinload(User.client))
        .order_by(User.is_active.desc(), User.full_name)
    )
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            (User.full_name.like(like)) | (User.username.like(like)) | (User.email.like(like))
        )
    operators = db.scalars(stmt).all()
    clients = db.scalars(select(Client).order_by(Client.name)).all()
    return render(
        request,
        "operators/list.html",
        {"user": user, "operators": operators, "clients": clients, "q": q or ""},
    )


@router.post("/operadores")
def operators_create(
    request: Request,
    full_name: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(""),
    client_id: str = Form(""),
    is_superuser: str = Form(""),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    username = username.strip().lower()
    email = email.strip().lower()
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(status_code=400, detail="username já em uso.")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=400, detail="email já em uso.")
    new = User(
        full_name=full_name.strip(),
        username=username,
        email=email,
        password_hash=hash_password(password) if password else None,
        client_id=int(client_id) if client_id else None,
        is_superuser=is_superuser == "on",
        is_active=is_active == "on",
    )
    db.add(new)
    db.flush()
    audit.record(db, "operator.create", actor=user, target_type="user", target_id=new.id,
                 description=f"Criou operador {new.username}", request=request, commit=False)
    db.commit()
    return RedirectResponse("/operadores", status_code=status.HTTP_302_FOUND)


@router.post("/operadores/{user_id}/editar")
def operators_update(
    user_id: int,
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(""),
    client_id: str = Form(""),
    is_superuser: str = Form(""),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    target = db.get(User, user_id) or _404("Operador")
    target.full_name = full_name.strip()
    target.email = email.strip().lower()
    if password:
        target.password_hash = hash_password(password)
    target.client_id = int(client_id) if client_id else None
    target.is_superuser = is_superuser == "on"
    was_active = target.is_active
    target.is_active = is_active == "on"
    action = "operator.update"
    if not was_active and target.is_active:
        action = "operator.activate"
    audit.record(db, action, actor=user, target_type="user", target_id=target.id,
                 description=f"Atualizou operador {target.username}", request=request, commit=False)
    db.commit()
    return RedirectResponse(_back(request, "/operadores"), status_code=status.HTTP_302_FOUND)


@router.get("/operadores/{user_id}/permissoes")
def operator_permissions(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    target = db.get(User, user_id) or _404("Operador")
    apps = db.scalars(
        select(Application)
        .options(selectinload(Application.permissions))
        .order_by(Application.name)
    ).all()
    granted = {
        a.permission_id
        for a in db.scalars(
            select(UserAppPermission).where(UserAppPermission.user_id == user_id)
        ).all()
    }
    return render(
        request,
        "operators/permissions.html",
        {"user": user, "target": target, "apps": apps, "granted": granted},
    )


@router.post("/operadores/{user_id}/permissoes")
async def operator_permissions_save(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    target = db.get(User, user_id) or _404("Operador")
    form = await request.form()
    selected = {int(v) for v in form.getlist("permission_id")}

    current = {
        a.permission_id: a
        for a in db.scalars(
            select(UserAppPermission).where(UserAppPermission.user_id == user_id)
        ).all()
    }
    all_perms = {p.id: p for p in db.scalars(select(Permission)).all()}

    added, removed = 0, 0
    for pid in selected - current.keys():
        if pid in all_perms:
            perm_service.grant(db, user=target, permission=all_perms[pid], granted_by=user)
            added += 1
    for pid in current.keys() - selected:
        perm_service.revoke(db, user=target, permission=all_perms[pid])
        removed += 1

    if added or removed:
        audit.record(
            db, "permission.sync", actor=user, target_type="user", target_id=target.id,
            description=f"Permissões de {target.username}: +{added} / -{removed}",
            request=request, meta={"added": added, "removed": removed}, commit=False,
        )
    db.commit()
    return RedirectResponse(
        f"/operadores/{user_id}/permissoes", status_code=status.HTTP_302_FOUND
    )


# --------------------------------------------------------------------------- #
# Aplicações
# --------------------------------------------------------------------------- #
@router.get("/apps")
def apps_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    apps = db.scalars(
        select(Application)
        .options(selectinload(Application.client), selectinload(Application.permissions))
        .order_by(Application.name)
    ).all()
    clients = db.scalars(select(Client).order_by(Client.name)).all()
    new_secret = request.session.pop("new_app_secret", None)
    return render(
        request,
        "apps/list.html",
        {"user": user, "apps": apps, "clients": clients, "new_secret": new_secret},
    )


@router.post("/apps")
def apps_create(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    description: str = Form(""),
    base_url: str = Form(""),
    redirect_uris: str = Form(""),
    client_id: str = Form(""),
    allowed_scopes: str = Form("openid profile email"),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    slug = slug.strip().lower()
    if db.scalar(select(Application).where(Application.slug == slug)):
        raise HTTPException(status_code=400, detail="slug já em uso.")
    secret = generate_client_secret()
    app = Application(
        name=name.strip(),
        slug=slug,
        description=description.strip() or None,
        base_url=base_url.strip() or None,
        redirect_uris=redirect_uris.strip(),
        client_id=int(client_id) if client_id else None,
        allowed_scopes=allowed_scopes.strip() or "openid profile email",
        oauth_client_id=generate_client_id(),
        oauth_client_secret_hash=hash_password(secret),
    )
    db.add(app)
    db.flush()
    audit.record(db, "app.create", actor=user, target_type="application", target_id=app.id,
                 description=f"Registrou app {app.slug}", request=request, commit=False)
    db.commit()
    request.session["new_app_secret"] = {
        "slug": app.slug,
        "client_id": app.oauth_client_id,
        "client_secret": secret,
    }
    return RedirectResponse("/apps", status_code=status.HTTP_302_FOUND)


@router.post("/apps/{app_id}/editar")
def apps_update(
    app_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    base_url: str = Form(""),
    redirect_uris: str = Form(""),
    client_id: str = Form(""),
    allowed_scopes: str = Form("openid profile email"),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    app = db.get(Application, app_id) or _404("Aplicação")
    app.name = name.strip()
    app.description = description.strip() or None
    app.base_url = base_url.strip() or None
    app.redirect_uris = redirect_uris.strip()
    app.client_id = int(client_id) if client_id else None
    app.allowed_scopes = allowed_scopes.strip() or "openid profile email"
    app.is_active = is_active == "on"
    audit.record(db, "app.update", actor=user, target_type="application", target_id=app.id,
                 description=f"Editou app {app.slug}", request=request, commit=False)
    db.commit()
    return RedirectResponse("/apps", status_code=status.HTTP_302_FOUND)


@router.post("/apps/{app_id}/rotacionar-segredo")
def apps_rotate_secret(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    app = db.get(Application, app_id) or _404("Aplicação")
    secret = generate_client_secret()
    app.oauth_client_secret_hash = hash_password(secret)
    audit.record(db, "app.rotate_secret", actor=user, target_type="application",
                 target_id=app.id, description=f"Rotacionou segredo de {app.slug}",
                 request=request, commit=False)
    db.commit()
    request.session["new_app_secret"] = {
        "slug": app.slug,
        "client_id": app.oauth_client_id,
        "client_secret": secret,
    }
    return RedirectResponse("/apps", status_code=status.HTTP_302_FOUND)


@router.post("/apps/{app_id}/permissoes")
def apps_add_permission(
    app_id: int,
    request: Request,
    code: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    app = db.get(Application, app_id) or _404("Aplicação")
    code = code.strip()
    if db.scalar(
        select(Permission).where(
            Permission.application_id == app_id, Permission.code == code
        )
    ):
        raise HTTPException(status_code=400, detail="Permissão já existe neste app.")
    db.add(
        Permission(
            application_id=app_id,
            code=code,
            name=name.strip(),
            description=description.strip() or None,
        )
    )
    audit.record(db, "permission.create", actor=user, target_type="application",
                 target_id=app_id, description=f"Nova permissão {code} em {app.slug}",
                 request=request, commit=False)
    db.commit()
    return RedirectResponse("/apps", status_code=status.HTTP_302_FOUND)


@router.post("/apps/{app_id}/permissoes/{perm_id}/remover")
def apps_delete_permission(
    app_id: int,
    perm_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_admin),
):
    perm = db.get(Permission, perm_id)
    if perm and perm.application_id == app_id:
        db.delete(perm)
        audit.record(db, "permission.delete", actor=user, target_type="application",
                     target_id=app_id, description=f"Removeu permissão {perm.code}",
                     request=request, commit=False)
        db.commit()
    return RedirectResponse("/apps", status_code=status.HTTP_302_FOUND)


# --------------------------------------------------------------------------- #
# Auditoria
# --------------------------------------------------------------------------- #
@router.get("/auditoria")
def audit_list(
    request: Request,
    action: str | None = None,
    ator: str | None = None,
    page: int = 1,
    db: Session = Depends(get_db),
    user: User = Depends(require_web_user),
):
    page = max(page, 1)
    per_page = 40
    stmt = (
        select(AuditEvent)
        .options(selectinload(AuditEvent.actor))
        .order_by(AuditEvent.created_at.desc())
    )
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if ator:
        like = f"%{ator.strip()}%"
        stmt = stmt.join(User, AuditEvent.actor_user_id == User.id, isouter=True).where(
            (User.full_name.like(like))
            | (User.username.like(like))
            | (AuditEvent.actor_label.like(like))
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    events = db.scalars(stmt.limit(per_page).offset((page - 1) * per_page)).all()
    actions = db.scalars(
        select(AuditEvent.action).distinct().order_by(AuditEvent.action)
    ).all()
    return render(
        request,
        "audit/list.html",
        {
            "user": user,
            "events": events,
            "actions": actions,
            "action": action or "",
            "ator": ator or "",
            "page": page,
            "pages": max((total + per_page - 1) // per_page, 1),
            "total": total,
        },
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _404(what: str):
    raise HTTPException(status_code=404, detail=f"{what} não encontrado(a).")
