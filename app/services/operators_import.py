"""Importação em massa de clientes, usuários e permissões de UM sistema.

Mesmo padrão de app_import.py: parse -> plano/preview -> confirmar. O JSON
vem do lado do sistema satélite (ex.: Regula RPPS) e traz:

  {"app_slug": "regula-rpps",
   "clients": [{"code": "ABC", "name": "Prefeitura X", "city": null}],
   "users": [{"email": "a@b.com", "full_name": "Fulano", "username": "opcional",
              "client_code": "ABC" | null, "is_superuser": false,
              "permissions": ["crp_compliance", "pro_gestao"]}]}

Regras (todas pensadas pra ser seguro rodar de novo, e de novo):
- Upsert idempotente: Client por code, User por e-mail. Nada é apagado.
- Usuário novo nasce SEM senha (password_hash nulo) e ativo. Usuário que já
  existe NÃO tem is_active alterado (nunca reativa/desativa ninguém aqui).
- Permissões: só concede códigos que já existem no catálogo do sistema;
  códigos desconhecidos viram aviso, não param a importação. Nunca remove
  permissão que o usuário já tenha.
- is_superuser só PROMOVE (nunca rebaixa) e sai destacado no preview: no APP
  CENTRAL isso dá acesso de administrador a TUDO, não só a este sistema —
  admins "de plataforma" de um satélite normalmente devem receber apenas as
  permissões dele (ex.: admin_*), não is_superuser.
- Referência a client_code que não está em "clients" nem no banco é erro do
  arquivo (para tudo antes de gravar qualquer coisa).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.models import (
    Application,
    Client,
    ClientTier,
    User,
    UserAppClient,
    UserAppPermission,
)
from app.services import permissions as perm_service

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
_USERNAME_BAD = re.compile(r"[^a-z0-9._-]+")


class SpecError(ValueError):
    """Arquivo inválido — a mensagem pode ter várias linhas (uma por problema)."""


@dataclass
class ClientPlanItem:
    code: str
    name: str
    city: str | None
    action: str  # "create" | "update" | "unchanged"


@dataclass
class UserPlanItem:
    email: str
    full_name: str
    username: str
    client_code: str | None
    is_superuser: bool
    action: str  # "create" | "update" | "unchanged"
    grant_codes: list[str] = field(default_factory=list)  # a conceder agora
    already_granted: int = 0
    promote_superuser: bool = False


@dataclass
class ImportPlan:
    app_slug: str
    app_name: str
    client_items: list[ClientPlanItem] = field(default_factory=list)
    user_items: list[UserPlanItem] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _count(self, items, action: str) -> int:
        return sum(1 for i in items if i.action == action)

    @property
    def clients_create(self) -> int:
        return self._count(self.client_items, "create")

    @property
    def clients_update(self) -> int:
        return self._count(self.client_items, "update")

    @property
    def users_create(self) -> int:
        return self._count(self.user_items, "create")

    @property
    def users_update(self) -> int:
        return self._count(self.user_items, "update")

    @property
    def users_unchanged(self) -> int:
        return self._count(self.user_items, "unchanged")

    @property
    def grants_total(self) -> int:
        return sum(len(u.grant_codes) for u in self.user_items)

    @property
    def superuser_promotions(self) -> list[UserPlanItem]:
        return [u for u in self.user_items if u.promote_superuser]


# --------------------------------------------------------------------------- #
# parse
# --------------------------------------------------------------------------- #
def parse_spec(raw_text: str) -> dict:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        raise SpecError("Cole o JSON gerado pelo sistema satélite.")
    try:
        spec = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SpecError(f"JSON inválido: {exc.msg} (linha {exc.lineno}, coluna {exc.colno}).") from exc
    if not isinstance(spec, dict):
        raise SpecError("O JSON precisa ser um objeto na raiz.")
    if not str(spec.get("app_slug") or "").strip():
        raise SpecError('Falta "app_slug" (slug do sistema já cadastrado em Sistemas).')
    if not isinstance(spec.get("users"), list):
        raise SpecError('Falta "users" (lista de usuários).')
    if spec.get("clients") is not None and not isinstance(spec.get("clients"), list):
        raise SpecError('"clients" precisa ser uma lista.')
    return spec


def _sanitize_username(base: str) -> str:
    base = _USERNAME_BAD.sub(".", base.strip().lower())
    base = re.sub(r"\.{2,}", ".", base).strip("._-")
    return (base or "user")[:64]


def _unique_username(base: str, taken: set[str]) -> str:
    candidate = _sanitize_username(base)
    if candidate not in taken:
        return candidate
    i = 2
    while True:
        suffix = str(i)
        cand = f"{candidate[: 64 - len(suffix)]}{suffix}"
        if cand not in taken:
            return cand
        i += 1


# --------------------------------------------------------------------------- #
# plano (não grava nada)
# --------------------------------------------------------------------------- #
def build_plan(db: Session, spec: dict) -> ImportPlan:
    slug = str(spec["app_slug"]).strip().lower()
    app = db.scalar(select(Application).where(Application.slug == slug))
    if app is None:
        raise SpecError(
            f'Sistema "{slug}" não está cadastrado. Cadastre/importe o catálogo dele '
            "em Sistemas antes de importar usuários."
        )
    catalog = {p.code: p for p in app.permissions}

    errors: list[str] = []
    plan = ImportPlan(app_slug=app.slug, app_name=app.name)

    # ---- clientes ---------------------------------------------------------- #
    db_clients = {c.code: c for c in db.scalars(select(Client)).all()}
    payload_client_codes: set[str] = set()
    for idx, raw in enumerate(spec.get("clients") or [], start=1):
        if not isinstance(raw, dict):
            errors.append(f"clients[{idx}]: precisa ser um objeto.")
            continue
        code = str(raw.get("code") or "").strip().upper()
        if not code:
            errors.append(f"clients[{idx}]: falta 'code'.")
            continue
        if len(code) > 32:
            errors.append(f"clients[{idx}]: code '{code}' passa de 32 caracteres.")
            continue
        if code in payload_client_codes:
            errors.append(f"clients: code '{code}' aparece mais de uma vez.")
            continue
        payload_client_codes.add(code)

        existing = db_clients.get(code)
        name = str(raw.get("name") or "").strip() or (existing.name if existing else "")
        if not name:
            errors.append(f"clients[{idx}] ({code}): falta 'name'.")
            continue
        city = (str(raw.get("city")).strip() or None) if raw.get("city") else None

        if existing is None:
            action = "create"
        elif existing.name != name or (city and existing.city != city):
            action = "update"
        else:
            action = "unchanged"
        plan.client_items.append(ClientPlanItem(code, name[:200], city, action))

    known_client_codes = set(db_clients) | payload_client_codes

    # ---- usuários ---------------------------------------------------------- #
    entries: list[tuple[int, dict, str]] = []
    seen_emails: set[str] = set()
    for idx, raw in enumerate(spec["users"], start=1):
        if not isinstance(raw, dict):
            errors.append(f"users[{idx}]: precisa ser um objeto.")
            continue
        email = str(raw.get("email") or "").strip().lower()
        if not email or not _EMAIL_RE.match(email) or len(email) > 254:
            errors.append(f"users[{idx}]: e-mail inválido ({raw.get('email')!r}).")
            continue
        if email in seen_emails:
            errors.append(f"users: e-mail '{email}' aparece mais de uma vez.")
            continue
        seen_emails.add(email)
        client_code = str(raw.get("client_code") or "").strip().upper() or None
        if client_code and client_code not in known_client_codes:
            errors.append(
                f"users[{idx}] ({email}): client_code '{client_code}' não está em "
                "'clients' nem cadastrado no APP CENTRAL."
            )
            continue
        entries.append((idx, raw, email))

    if errors:
        raise SpecError("\n".join(errors))

    existing_users = {
        u.email: u
        for u in db.scalars(
            select(User).where(User.email.in_([e for _, _, e in entries]))
        ).all()
    } if entries else {}
    taken_usernames: set[str] = set(db.scalars(select(User.username)).all())
    existing_grants: set[tuple[int, int]] = set()
    if existing_users:
        existing_grants = {
            (g.user_id, g.permission_id)
            for g in db.scalars(
                select(UserAppPermission).where(
                    UserAppPermission.application_id == app.id,
                    UserAppPermission.user_id.in_([u.id for u in existing_users.values()]),
                )
            ).all()
        }
    client_by_code = db_clients
    # cliente atual de cada usuário existente NESTE sistema (e não no cadastro geral)
    current_app_client: dict[int, int] = {}
    if existing_users:
        current_app_client = {
            r.user_id: r.client_id
            for r in db.scalars(
                select(UserAppClient).where(
                    UserAppClient.application_id == app.id,
                    UserAppClient.user_id.in_([u.id for u in existing_users.values()]),
                )
            ).all()
        }

    for _, raw, email in entries:
        existing = existing_users.get(email)
        local_part = email.split("@", 1)[0]
        full_name = str(raw.get("full_name") or "").strip() or local_part
        client_code = str(raw.get("client_code") or "").strip().upper() or None
        wants_super = bool(raw.get("is_superuser"))

        if existing is not None:
            username = existing.username
        else:
            wanted = str(raw.get("username") or "").strip() or local_part
            username = _unique_username(wanted, taken_usernames)
            if raw.get("username") and _sanitize_username(str(raw["username"])) != username:
                plan.warnings.append(
                    f"{email}: username '{raw['username']}' já em uso ou inválido — "
                    f"vai usar '{username}'."
                )
            taken_usernames.add(username)

        # permissões
        grant_codes: list[str] = []
        already = 0
        seen_codes: set[str] = set()
        for code in raw.get("permissions") or []:
            code = str(code).strip()
            if not code or code in seen_codes:
                continue
            seen_codes.add(code)
            perm = catalog.get(code)
            if perm is None:
                plan.warnings.append(
                    f"{email}: permissão desconhecida '{code}' (não existe no catálogo de "
                    f"{app.slug}) — ignorada."
                )
            elif existing is not None and (existing.id, perm.id) in existing_grants:
                already += 1
            else:
                grant_codes.append(code)

        # ação
        changed = False
        promote = False
        if existing is None:
            action = "create"
            promote = wants_super
        else:
            if existing.full_name != full_name and str(raw.get("full_name") or "").strip():
                changed = True
            if client_code:
                target_client = client_by_code.get(client_code)
                current_id = current_app_client.get(existing.id)
                target_id = target_client.id if target_client else None
                if target_client is None or current_id != target_id:
                    changed = True
                    if current_id is not None:
                        old = next((c.code for c in client_by_code.values() if c.id == current_id), "?")
                        plan.warnings.append(
                            f"{email}: cliente vai mudar de {old} para {client_code}."
                        )
            if wants_super and not existing.is_superuser:
                changed = True
                promote = True
            if not existing.is_active:
                plan.warnings.append(
                    f"{email}: usuário existente está INATIVO — continua inativo "
                    "(a importação não reativa ninguém)."
                )
            action = "update" if (changed or grant_codes) else "unchanged"

        plan.user_items.append(
            UserPlanItem(
                email=email,
                full_name=full_name[:200],
                username=username,
                client_code=client_code,
                is_superuser=wants_super or bool(existing and existing.is_superuser),
                action=action,
                grant_codes=grant_codes,
                already_granted=already,
                promote_superuser=promote,
            )
        )

    for u in plan.superuser_promotions:
        plan.warnings.append(
            f"{u.email}: será ADMINISTRADOR do APP CENTRAL INTEIRO (is_superuser) — "
            "confirme que não deveria receber só as permissões deste sistema."
        )
    return plan


# --------------------------------------------------------------------------- #
# aplicar (uma transação, auditoria única)
# --------------------------------------------------------------------------- #
def apply_plan(db: Session, plan: ImportPlan, *, actor: User, request) -> dict:
    app = db.scalar(select(Application).where(Application.slug == plan.app_slug))
    if app is None:  # sumiu entre o preview e a confirmação
        raise SpecError(f'Sistema "{plan.app_slug}" não existe mais.')
    catalog = {p.code: p for p in app.permissions}

    clients = {c.code: c for c in db.scalars(select(Client)).all()}
    clients_created = clients_updated = 0
    for item in plan.client_items:
        current = clients.get(item.code)
        if current is None:
            current = Client(code=item.code, name=item.name, city=item.city, tier=ClientTier.BRONZE)
            db.add(current)
            clients[item.code] = current
            clients_created += 1
        elif item.action == "update":
            current.name = item.name
            if item.city:
                current.city = item.city
            clients_updated += 1
    db.flush()

    existing = {
        u.email: u
        for u in db.scalars(select(User).where(User.email.in_([i.email for i in plan.user_items]))).all()
    } if plan.user_items else {}

    users_created = users_updated = users_unchanged = grants_added = 0
    new_user_ids: list[int] = []
    for item in plan.user_items:
        user = existing.get(item.email)
        client = clients.get(item.client_code) if item.client_code else None
        if user is None:
            user = User(
                username=item.username,
                email=item.email,
                full_name=item.full_name,
                password_hash=None,
                is_superuser=item.is_superuser,
                is_active=True,
            )
            db.add(user)
            db.flush()
            users_created += 1
            new_user_ids.append(user.id)
            if client is not None:
                db.add(UserAppClient(user_id=user.id, application_id=app.id, client_id=client.id))
        else:
            touched = False
            if item.full_name and user.full_name != item.full_name:
                user.full_name = item.full_name
                touched = True
            if client is not None:
                link = db.scalar(
                    select(UserAppClient).where(
                        UserAppClient.user_id == user.id,
                        UserAppClient.application_id == app.id,
                    )
                )
                if link is None:
                    db.add(UserAppClient(user_id=user.id, application_id=app.id, client_id=client.id))
                    touched = True
                elif link.client_id != client.id:
                    link.client_id = client.id
                    touched = True
            if item.promote_superuser and not user.is_superuser:
                user.is_superuser = True
                touched = True
            if touched or item.grant_codes:
                users_updated += 1
            else:
                users_unchanged += 1

        for code in item.grant_codes:
            perm = catalog.get(code)
            if perm is not None:
                # grant() é idempotente; grant_codes já exclui o que existia no preview
                perm_service.grant(db, user=user, permission=perm, granted_by=actor)
                grants_added += 1

    summary = {
        "app_slug": plan.app_slug,
        "clients_created": clients_created,
        "clients_updated": clients_updated,
        "users_created": users_created,
        "users_updated": users_updated,
        "users_unchanged": users_unchanged,
        "grants_added": grants_added,
        "warnings": len(plan.warnings),
    }
    audit.record(
        db,
        "users.import_spec",
        actor=actor,
        target_type="application",
        target_id=app.id,
        description=(
            f"Importou usuários de {app.slug}: {users_created} novo(s), {users_updated} "
            f"atualizado(s), {grants_added} permissão(ões) concedida(s), "
            f"{clients_created} cliente(s) novo(s)"
        ),
        request=request,
        meta=summary,
        commit=False,
    )
    db.commit()
    # ids dos usuários NOVOS (pra gerar os links de senha) — fora do meta da auditoria
    return {**summary, "new_user_ids": new_user_ids}
