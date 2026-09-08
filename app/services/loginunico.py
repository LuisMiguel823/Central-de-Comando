"""Cliente do "Login Único" municipal (Neomind Fusion — fluxo WSAuth).

Fluxo em 3 passos (ver doc da prefeitura):

  1. GET  {base}/WSAuthInit_edu.rule?sys={sys}&redirect={callback}
         -> {"expires_in": "...", "location": "...form.jsp?...&token=XXX", "token": "XXX"}
  2. Redireciona o navegador para "location"; o usuário faz login lá.
  3. GET  {base}/WSAuthVerify_edu.rule?sys={sys}&token=XXX
         -> dados do usuário (nome, e-mail, CPF, foto, nível da conta)
         ATENÇÃO: a consulta do passo 3 só pode ser feita UMA vez por token.

Cada câmara pode ter a própria instância (host/sys). A resolução é:
Client.loginunico_base_url  ->  senão  ->  settings.loginunico_*
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.config import settings
from app.models import Client


@dataclass
class Instance:
    base_url: str
    sys: str

    @property
    def init_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/WSAuthInit_edu.rule"

    @property
    def verify_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/WSAuthVerify_edu.rule"


def is_configured() -> bool:
    return bool(settings.loginunico_enabled and settings.loginunico_base_url)


def resolve_instance(client: Client | None) -> Instance:
    if client and client.loginunico_base_url:
        return Instance(
            base_url=client.loginunico_base_url,
            sys=client.loginunico_sys or settings.loginunico_sys,
        )
    return Instance(base_url=settings.loginunico_base_url, sys=settings.loginunico_sys)


# --- seam de rede (monkeypatchável em testes) -------------------------------- #
def _http_get(url: str, params: dict) -> dict:
    with httpx.Client(
        timeout=settings.loginunico_timeout, verify=settings.loginunico_verify_ssl
    ) as c:
        resp = c.get(url, params=params)
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        return {"_raw": resp.text}


# --- passos -------------------------------------------------------------------- #
def init_auth(instance: Instance, redirect_url: str) -> dict:
    """Passo 1. Retorna {location, token, expires_in}."""
    data = _http_get(
        instance.init_url, {"sys": instance.sys, "redirect": redirect_url}
    )
    if not data.get("location") or not data.get("token"):
        raise RuntimeError(f"WSAuthInit sem location/token: {data}")
    return data


def verify_auth(instance: Instance, token: str) -> dict:
    """Passo 3. Consulta ÚNICA. Retorna dados normalizados do usuário."""
    raw = _http_get(instance.verify_url, {"sys": instance.sys, "token": token})
    return normalize_user(raw)


# --- normalização (as chaves do Fusion variam entre instâncias) -------------- #
def _pick(d: dict, *keys: str) -> str | None:
    for k in keys:
        for cand in (k, k.upper(), k.lower(), k.capitalize()):
            if cand in d and d[cand] not in (None, "", "null"):
                return str(d[cand]).strip()
    return None


def normalize_user(raw: dict) -> dict:
    name = _pick(raw, "nome", "nome_completo", "nomeCompleto", "name", "fullname")
    email = _pick(raw, "email", "e-mail", "e_mail", "mail")
    cpf_raw = _pick(raw, "cpf", "documento", "doc")
    photo = _pick(raw, "foto", "foto_url", "fotoUrl", "photo", "picture", "avatar")
    level = _pick(raw, "nivel", "nivel_conta", "nivelConta", "level", "nivel_da_conta")

    cpf = "".join(ch for ch in (cpf_raw or "") if ch.isdigit()) or None
    try:
        level_int = int(level) if level is not None else None
    except ValueError:
        level_int = None

    ok = bool(name or cpf or email)
    return {
        "ok": ok,
        "name": name,
        "email": (email or "").lower() or None,
        "cpf": cpf,
        "photo_url": photo,
        "account_level": level_int,
        "raw": raw,
    }
