from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.config import settings
from app.core.deps import RedirectToLogin
from app.core.templating import render
from app.database import create_all, engine
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
    return {"status": "ok", "app": settings.app_name, "version": __version__}
