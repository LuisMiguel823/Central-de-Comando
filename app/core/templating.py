from __future__ import annotations

import zlib
from datetime import datetime
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
        "DIAMANTE": "bg-brand-100 text-brand-700",
    }.get(tier, "bg-slate-100 text-slate-600")


templates.env.filters["tier_badge"] = tier_badge

# Cor automática de cada módulo (sistema): estável, sai do slug. Triplas RGB
# usadas como `--hue` no CSS (rgb(var(--hue) / .x)).
_MODULE_HUES = [
    "16 178 122",  # esmeralda
    "139 92 246",  # violeta
    "245 158 11",  # âmbar
    "244 63 94",  # rosa
    "20 184 166",  # turquesa
    "249 115 22",  # laranja
    "217 70 239",  # fúcsia
    "99 102 241",  # índigo
]


def module_hue(key: str) -> str:
    return _MODULE_HUES[zlib.crc32((key or "").encode()) % len(_MODULE_HUES)]


def initials(name: str) -> str:
    parts = [p for p in (name or "").replace("-", " ").split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[1][0]).upper()


def ago(dt: datetime | None, now: datetime | None = None) -> str:
    """'agora', 'há 5 min', 'há 3 h', 'há 2 d' — ou a data, se for antigo."""
    if dt is None:
        return "—"
    now = now or datetime.now()
    secs = int((now - dt).total_seconds())
    if secs < 45:
        return "agora"
    if secs < 3600:
        return f"há {max(1, secs // 60)} min"
    if secs < 86400:
        return f"há {secs // 3600} h"
    if secs < 86400 * 7:
        return f"há {secs // 86400} d"
    return dt.strftime("%d/%m/%Y")


_CATEGORY_LABELS = {"admin": "Administração global", "geral": "Geral"}


def cat_label(category: str) -> str:
    return _CATEGORY_LABELS.get(category, category.replace("_", " ").title())


templates.env.filters["cat_label"] = cat_label
templates.env.filters["module_hue"] = module_hue
templates.env.filters["initials"] = initials
templates.env.filters["ago"] = ago


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
