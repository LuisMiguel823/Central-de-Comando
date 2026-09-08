"""Popula o banco com dados iniciais.

Uso:
    python -m scripts.seed             # cria/atualiza o admin e o conjunto demo
    python -m scripts.seed --if-empty  # só roda se ainda não houver usuários
    python -m scripts.seed --admin-only
"""
from __future__ import annotations

import sys

from sqlalchemy import func, select

from app.config import settings
from app.core.security import (
    generate_client_id,
    generate_client_secret,
    hash_password,
)
from app.database import SessionLocal, create_all
from app.models import (
    Application,
    Client,
    ClientTier,
    Permission,
    User,
)

# Câmaras do quadro (código, nome, cidade, plano, [base_url do Login Único])
CLIENTS = [
    ("CMSPA", "Câmara Municipal de Santarém", "Santarém/PA", ClientTier.DIAMANTE, None),
    ("CMCF", "Câmara Municipal de Cachoeira do Arari", "Cachoeira do Arari/PA", ClientTier.DIAMANTE, None),
    ("CMM", "Câmara Municipal de Muaná", "Muaná/PA", ClientTier.DIAMANTE, None),
    ("CMAC", "Câmara Municipal de Acará", "Acará/PA", ClientTier.OURO, None),
    ("CMRO", "Câmara Municipal de Rondon do Pará", "Rondon do Pará/PA", ClientTier.OURO, None),
    ("CMCA", "Câmara Municipal de Canaã dos Carajás", "Canaã dos Carajás/PA", ClientTier.DIAMANTE, None),
    ("CMMESQ", "Câmara Municipal de Mesquita", "Mesquita/RJ", ClientTier.DIAMANTE, None),
    ("CMSAQ", "Câmara Municipal de Saquarema", "Saquarema/RJ", ClientTier.DIAMANTE, None),
    ("CMCABO", "Câmara Municipal de Cabo Frio", "Cabo Frio/RJ", ClientTier.DIAMANTE,
     "https://loginunico.cabofrio.rj.gov.br/loginunico"),
]

# Apps satélite + catálogo de permissões
APPS = [
    {
        "name": "Protocolo Digital",
        "slug": "app-1",
        "base_url": "http://localhost:8101",
        "redirects": ["http://localhost:8101/auth/callback"],
        "perms": [
            ("protocolo.ler", "Ver protocolos"),
            ("protocolo.criar", "Abrir protocolo"),
            ("protocolo.tramitar", "Tramitar protocolo"),
            ("protocolo.arquivar", "Arquivar protocolo"),
        ],
    },
    {
        "name": "Portal do Cidadão (WWW)",
        "slug": "app-2",
        "base_url": "http://localhost:8102",
        "redirects": ["http://localhost:8102/auth/callback"],
        "perms": [
            ("portal.publicar", "Publicar conteúdo"),
            ("portal.moderar", "Moderar comentários"),
            ("portal.relatorios", "Ver relatórios de acesso"),
        ],
    },
    {
        "name": "Gestão de Contratos",
        "slug": "app-3",
        "base_url": "http://localhost:8103",
        "redirects": ["http://localhost:8103/auth/callback"],
        "perms": [
            ("contratos.ler", "Ver contratos"),
            ("contratos.editar", "Editar contratos"),
            ("contratos.assinar", "Assinar contratos"),
            ("contratos.excluir", "Excluir contratos"),
        ],
    },
]


def seed(admin_only: bool = False) -> None:
    create_all()
    db = SessionLocal()
    try:
        # --- Admin ---
        admin = db.scalar(
            select(User).where(User.username == settings.bootstrap_admin_username)
        )
        if admin is None:
            admin = User(
                username=settings.bootstrap_admin_username,
                email=settings.bootstrap_admin_email,
                full_name="Administrador",
                password_hash=hash_password(settings.bootstrap_admin_password),
                is_superuser=True,
                is_active=True,
            )
            db.add(admin)
            print(f"Admin criado: {admin.username} / {settings.bootstrap_admin_password}")
        else:
            print(f"Admin já existe: {admin.username}")

        if admin_only:
            db.commit()
            return

        # --- Clientes ---
        for code, name, city, tier, lu_url in CLIENTS:
            if not db.scalar(select(Client).where(Client.code == code)):
                db.add(
                    Client(
                        code=code,
                        name=name,
                        city=city,
                        tier=tier,
                        loginunico_base_url=lu_url,
                    )
                )
                print(f"Cliente: {code}")
        db.flush()

        # --- Apps + permissões ---
        for spec in APPS:
            app = db.scalar(select(Application).where(Application.slug == spec["slug"]))
            if app is None:
                secret = generate_client_secret()
                app = Application(
                    name=spec["name"],
                    slug=spec["slug"],
                    base_url=spec["base_url"],
                    redirect_uris="\n".join(spec["redirects"]),
                    oauth_client_id=generate_client_id(),
                    oauth_client_secret_hash=hash_password(secret),
                    allowed_scopes="openid profile email",
                )
                db.add(app)
                db.flush()
                print(f"App: {app.slug}  client_id={app.oauth_client_id}  client_secret={secret}")
            for code, pname in spec["perms"]:
                if not db.scalar(
                    select(Permission).where(
                        Permission.application_id == app.id, Permission.code == code
                    )
                ):
                    db.add(Permission(application_id=app.id, code=code, name=pname))

        db.commit()
        print("Seed concluído.")
    finally:
        db.close()


def main() -> int:
    args = set(sys.argv[1:])
    if "--if-empty" in args:
        db = SessionLocal()
        try:
            has_users = db.scalar(select(func.count(User.id))) or 0
        except Exception:
            has_users = 0
        finally:
            db.close()
        if has_users:
            print("Banco já populado — seed ignorado (--if-empty).")
            return 0
    seed(admin_only="--admin-only" in args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
