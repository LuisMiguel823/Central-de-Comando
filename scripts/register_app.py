"""Registra (ou atualiza) uma Aplicação satélite via linha de comando.

Uso:
    python -m scripts.register_app --name "MILVUS" --slug milvus \\
        --base-url https://atendimento.npibrasil.com \\
        --redirect-uri https://atendimento.npibrasil.com/auth/central/callback

Se já existir uma aplicação com esse slug, apenas atualiza base_url/redirect_uris
e mantém o client_id/secret existentes (não rotaciona sem pedir explicitamente).
Use --rotate-secret para forçar um novo client_secret.
"""
from __future__ import annotations

import argparse

from sqlalchemy import select

from app.core.security import generate_client_id, generate_client_secret, hash_password
from app.database import SessionLocal, create_all
from app.models import Application


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--redirect-uri", action="append", default=[], help="pode repetir")
    parser.add_argument("--scopes", default="openid profile email")
    parser.add_argument("--rotate-secret", action="store_true")
    args = parser.parse_args()

    create_all()
    db = SessionLocal()
    try:
        app = db.scalar(select(Application).where(Application.slug == args.slug))
        secret = None
        if app is None:
            secret = generate_client_secret()
            app = Application(
                name=args.name,
                slug=args.slug,
                base_url=args.base_url or None,
                redirect_uris="\n".join(args.redirect_uri),
                allowed_scopes=args.scopes,
                oauth_client_id=generate_client_id(),
                oauth_client_secret_hash=hash_password(secret),
            )
            db.add(app)
            print(f"Nova aplicação criada: {args.slug}")
        else:
            app.name = args.name
            if args.base_url:
                app.base_url = args.base_url
            if args.redirect_uri:
                app.redirect_uris = "\n".join(args.redirect_uri)
            app.allowed_scopes = args.scopes
            if args.rotate_secret:
                secret = generate_client_secret()
                app.oauth_client_secret_hash = hash_password(secret)
            print(f"Aplicação existente atualizada: {args.slug}")

        db.commit()
        db.refresh(app)

        print("\n--- credenciais OAuth ---")
        print(f"client_id:     {app.oauth_client_id}")
        if secret:
            print(f"client_secret: {secret}  (guarde agora — não é mostrado de novo)")
        else:
            print("client_secret: (inalterado — use --rotate-secret pra gerar um novo)")
        print(f"redirect_uris: {app.redirect_uris or '(nenhum)'}")
        print(f"scopes:        {app.allowed_scopes}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
