"""SSO Microsoft (Entra ID / Azure AD) — OAuth2 Authorization Code, sem lib.

Mesma abordagem já em produção no MILVUS: nada de msal/authlib. `httpx` puro.
Troca o `code` por `access_token` e usa o token pra chamar o Graph `/me`,
evitando validar assinatura de ID token (JWT) na mão.

Regra de negócio: **só autentica quem já existe** no APP CENTRAL (casado por
e-mail). Não cria operador automaticamente.
"""
from __future__ import annotations

from urllib.parse import urlencode

import httpx

from app.config import settings

GRAPH_ME = "https://graph.microsoft.com/v1.0/me"


def is_configured() -> bool:
    return bool(
        settings.microsoft_client_id
        and settings.microsoft_client_secret
        and settings.microsoft_tenant_id
    )


def _authority() -> str:
    return f"https://login.microsoftonline.com/{settings.microsoft_tenant_id}"


def authorize_url(state: str) -> str:
    params = {
        "client_id": settings.microsoft_client_id,
        "response_type": "code",
        "redirect_uri": settings.microsoft_redirect_uri,
        "response_mode": "query",
        "scope": settings.microsoft_scopes,
        "state": state,
    }
    return f"{_authority()}/oauth2/v2.0/authorize?{urlencode(params)}"


# --- seams de rede (monkeypatcháveis em testes) ----------------------------- #
def _http_post(url: str, data: dict) -> dict:
    with httpx.Client(timeout=settings.microsoft_timeout) as c:
        resp = c.post(url, data=data)
    resp.raise_for_status()
    return resp.json()


def _http_get(url: str, headers: dict) -> dict:
    with httpx.Client(timeout=settings.microsoft_timeout) as c:
        resp = c.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


# --- passos ---------------------------------------------------------------- #
def exchange_code(code: str) -> dict:
    """POST /token → dict com access_token."""
    data = {
        "client_id": settings.microsoft_client_id,
        "client_secret": settings.microsoft_client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.microsoft_redirect_uri,
        "scope": settings.microsoft_scopes,
    }
    token = _http_post(f"{_authority()}/oauth2/v2.0/token", data)
    if not token.get("access_token"):
        raise RuntimeError(f"Resposta de token sem access_token: {token}")
    return token


def get_me(access_token: str) -> dict:
    return _http_get(GRAPH_ME, {"Authorization": f"Bearer {access_token}"})


def email_from_me(me: dict) -> str | None:
    email = (me.get("mail") or me.get("userPrincipalName") or "").strip().lower()
    return email or None
