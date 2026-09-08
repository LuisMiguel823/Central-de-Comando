from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app import __version__
from app.config import settings

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals.update(
    {
        "app_name": settings.app_name,
        "app_version": __version__,
        "govbr_enabled": settings.govbr_enabled,
    }
)


def tier_badge(tier: str) -> str:
    """Classe Tailwind (tema claro) para o badge de plano do cliente."""
    return {
        "BRONZE": "bg-amber-100 text-amber-700",
        "PRATA": "bg-slate-100 text-slate-600",
        "OURO": "bg-yellow-100 text-yellow-700",
        "DIAMANTE": "bg-cyan-100 text-cyan-700",
    }.get(tier, "bg-slate-100 text-slate-600")


templates.env.filters["tier_badge"] = tier_badge


def render(
    request: Request,
    name: str,
    ctx: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
):
    data: dict[str, Any] = {"request": request, "current_path": request.url.path}
    if ctx:
        data.update(ctx)
    return templates.TemplateResponse(name, data, status_code=status_code)
