"""Importa a especificação (JSON) de um app satélite, gerada pelo prompt de
descoberta, e monta a Application + o catálogo de Permissions correspondente.

Nunca remove permissões automaticamente: um app satélite que já não tem mais
tela própria de usuários passa a depender 100% do catálogo daqui, então apagar
sem querer no reimport revogaria acesso de operador em produção. Permissões
que existem no banco mas sumiram do novo spec só entram em "orphaned_codes"
para o admin decidir manualmente.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import generate_client_id, generate_client_secret, hash_password
from app.models import Application, Permission, User
from app.core import audit

SUPPORTED_SCOPES = ["openid", "profile", "email"]
_ENV_PRIORITY = ("prod", "staging", "dev")


class SpecError(ValueError):
    """Spec JSON inválido ou faltando campo obrigatório."""


@dataclass
class PermissionPlanItem:
    code: str
    name: str
    description: str | None
    action: str  # "create" | "update" | "unchanged"


@dataclass
class ImportPlan:
    app_is_new: bool
    app_name: str
    app_slug: str
    base_url: str | None
    redirect_uris: str
    allowed_scopes: str
    permission_items: list[PermissionPlanItem] = field(default_factory=list)
    orphaned_codes: list[str] = field(default_factory=list)
    notes: str | None = None


def parse_spec(raw_text: str) -> dict:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        raise SpecError("Cole o JSON retornado pela IA do app satélite.")
    try:
        spec = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SpecError(f"JSON inválido: {exc.msg} (linha {exc.lineno}, coluna {exc.colno}).") from exc
    if not isinstance(spec, dict) or "app" not in spec:
        raise SpecError('JSON precisa ter um objeto raiz com a chave "app".')
    return spec


def _pick_env(values: dict | None, keys=_ENV_PRIORITY) -> str | None:
    if not isinstance(values, dict):
        return None
    for k in keys:
        v = values.get(k)
        if v:
            return str(v).strip()
    return None


def _merge_env(values: dict | None) -> str:
    if not isinstance(values, dict):
        return ""
    seen: list[str] = []
    for k in _ENV_PRIORITY:
        v = values.get(k)
        if v and str(v).strip() not in seen:
            seen.append(str(v).strip())
    return "\n".join(seen)


def build_plan(db: Session, spec: dict) -> ImportPlan:
    app_spec = spec.get("app") or {}
    name = str(app_spec.get("name") or "").strip()
    slug = str(app_spec.get("slug") or "").strip().lower()
    if not name or not slug:
        raise SpecError('"app.name" e "app.slug" são obrigatórios no JSON.')

    scopes_needed = app_spec.get("scopes_needed") or SUPPORTED_SCOPES
    allowed_scopes = " ".join(s for s in SUPPORTED_SCOPES if s in scopes_needed) or "openid"

    existing = db.scalar(select(Application).where(Application.slug == slug))

    items: list[PermissionPlanItem] = []
    existing_by_code: dict[str, Permission] = {}
    if existing:
        existing_by_code = {p.code: p for p in existing.permissions}

    for raw in spec.get("permissions") or []:
        code = str(raw.get("code") or "").strip()
        if not code:
            continue
        perm_name = str(raw.get("name") or code).strip()
        description = (raw.get("description") or "").strip() or None
        current = existing_by_code.get(code)
        if current is None:
            items.append(PermissionPlanItem(code, perm_name, description, "create"))
        elif current.name != perm_name or (current.description or None) != description:
            items.append(PermissionPlanItem(code, perm_name, description, "update"))
        else:
            items.append(PermissionPlanItem(code, perm_name, description, "unchanged"))

    spec_codes = {i.code for i in items}
    orphaned_codes = sorted(c for c in existing_by_code if c not in spec_codes)

    return ImportPlan(
        app_is_new=existing is None,
        app_name=name,
        app_slug=slug,
        base_url=_pick_env(app_spec.get("base_url")),
        redirect_uris=_merge_env(app_spec.get("redirect_uris")),
        allowed_scopes=allowed_scopes,
        permission_items=items,
        orphaned_codes=orphaned_codes,
        notes=(str(spec.get("notes")).strip() or None) if spec.get("notes") else None,
    )


def apply_plan(
    db: Session,
    plan: ImportPlan,
    *,
    actor: User,
    request,
) -> dict:
    app = db.scalar(select(Application).where(Application.slug == plan.app_slug))
    new_secret: dict | None = None

    if app is None:
        secret = generate_client_secret()
        app = Application(
            name=plan.app_name,
            slug=plan.app_slug,
            base_url=plan.base_url,
            redirect_uris=plan.redirect_uris,
            allowed_scopes=plan.allowed_scopes,
            oauth_client_id=generate_client_id(),
            oauth_client_secret_hash=hash_password(secret),
        )
        db.add(app)
        db.flush()
        new_secret = {
            "slug": app.slug,
            "client_id": app.oauth_client_id,
            "client_secret": secret,
        }
    else:
        app.name = plan.app_name
        if plan.base_url:
            app.base_url = plan.base_url
        if plan.redirect_uris:
            app.redirect_uris = plan.redirect_uris
        app.allowed_scopes = plan.allowed_scopes

    existing_by_code = {p.code: p for p in app.permissions}
    created = updated = 0
    for item in plan.permission_items:
        if item.action == "create":
            db.add(Permission(
                application_id=app.id,
                code=item.code,
                name=item.name,
                description=item.description,
            ))
            created += 1
        elif item.action == "update":
            perm = existing_by_code[item.code]
            perm.name = item.name
            perm.description = item.description
            updated += 1

    audit.record(
        db,
        "app.import_spec",
        actor=actor,
        target_type="application",
        target_id=app.id,
        description=(
            f"Importou especificação de {app.slug}: {created} permissão(ões) nova(s), "
            f"{updated} atualizada(s), {len(plan.orphaned_codes)} não encontrada(s) no novo spec"
        ),
        request=request,
        commit=False,
    )
    db.commit()

    return {
        "slug": app.slug,
        "app_is_new": new_secret is not None,
        "new_secret": new_secret,
        "created": created,
        "updated": updated,
        "orphaned_codes": plan.orphaned_codes,
    }
