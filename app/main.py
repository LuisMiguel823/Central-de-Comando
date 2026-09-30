from __future__ import annotations

import hashlib
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.config import settings
from app.core.deps import RedirectToLogin
from app.core.templating import render
from app.database import create_all, engine, get_db
from app.routers import api, auth, oauth, web_pages

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("central-comando")

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_tables:
        try:
            create_all()
            logger.info("Tabelas verificadas/criadas (AUTO_CREATE_TABLES=true).")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Não foi possível criar tabelas no startup: %s", exc)
    yield
    engine.dispose()


app = FastAPI(
    title=f"{settings.app_name} — APP CENTRAL",
    version=__version__,
    description="SSO / IAM central: login único, permissões, auditoria e federação gov.br.",
    lifespan=lifespan,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=settings.app_env == "prod",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(api.router)
app.include_router(web_pages.router)


@app.exception_handler(RedirectToLogin)
async def _redirect_to_login(request: Request, exc: RedirectToLogin):
    return RedirectResponse(
        f"/login?next={quote(exc.next_url, safe='')}", status_code=302
    )


@app.get("/health", include_in_schema=False)
def health():
    """Liveness pura — nunca toca o banco (usada só pra saber se o processo está de pé)."""
    return {"status": "ok", "app": settings.app_name, "version": __version__}


# Atualizar toda vez que uma migration nova for criada (não dá pra ler o
# diretório de migrations em runtime sem trazer o Alembic inteiro pra dentro
# do processo web por causa disso).
_EXPECTED_MIGRATION = "b7d2e41c9a3f"


def _status_key() -> str:
    """Chave só pra abrir o detalhe do /status (host/usuário/erro do driver).

    Derivada do SECRET_KEY pra não precisar de mais uma variável de ambiente:
    quem já tem acesso à configuração do servidor (única forma de ler o
    SECRET_KEY de verdade) consegue calcular essa chave; ninguém mais.
    """
    return hashlib.sha256(f"{settings.secret_key}:status".encode()).hexdigest()[:16]


@app.get("/status", include_in_schema=False)
def status_page(request: Request, db: Session = Depends(get_db), key: str = ""):
    """
    Diagnóstico público (sem login — o login também depende do banco, então uma
    página que exige login não ajuda justo quando o banco está fora). Sem a
    chave (?key=), mostra só "ok"/"com problema" — nada de host, usuário ou
    mensagem do driver, pra não expor infraestrutura interna pra qualquer
    visitante. Com a chave certa, mostra o detalhe completo.
    """
    detailed = key and secrets.compare_digest(key, _status_key())

    db_ok = False
    db_detail = None
    db_ms = None
    migration_ok = None
    current_migration = None

    t0 = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
        db_ms = round((time.perf_counter() - t0) * 1000)
        if detailed:
            try:
                current_migration = db.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar()
                migration_ok = current_migration == _EXPECTED_MIGRATION
            except Exception:  # noqa: BLE001
                migration_ok = None
    except Exception as exc:  # noqa: BLE001
        db_ms = round((time.perf_counter() - t0) * 1000)
        if detailed:
            # mensagem do driver ajuda a diagnosticar (usuário/host errado,
            # acesso negado, limite de conexões); só quem tem a chave vê.
            db_detail = f"{type(exc).__name__}: {str(exc)[:300]}"

    db_target = (
        f"{settings.db_user}@{settings.db_host}:{settings.db_port}/{settings.db_name}"
        if detailed
        else None
    )

    return render(
        request,
        "status.html",
        {
            "detailed": detailed,
            "db_ok": db_ok,
            "db_ms": db_ms,
            "db_detail": db_detail,
            "db_target": db_target,
            "migration_ok": migration_ok,
            "current_migration": current_migration,
            "expected_migration": _EXPECTED_MIGRATION,
        },
        status_code=200 if db_ok else 503,
    )
