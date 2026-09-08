"""Cliente OIDC para o Login Único gov.br (federação de identidade).

O APP CENTRAL delega a autenticação ao gov.br: redireciona o usuário para o
provedor, recebe o `code` de volta, troca por tokens e lê o `userinfo`.
Preencha GOVBR_CLIENT_ID / GOVBR_CLIENT_SECRET no .env para ativar de fato.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

import httpx
from authlib.integrations.starlette_client import OAuth

from app.config import settings

oauth = OAuth()

if settings.govbr_enabled and settings.govbr_client_id:
    oauth.register(
        name="govbr",
        client_id=settings.govbr_client_id,
        client_secret=settings.govbr_client_secret,
        server_metadata_url=settings.govbr_metadata_url,
        client_kwargs={
            "scope": settings.govbr_scopes,
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )


def is_configured() -> bool:
    return bool(
        settings.govbr_enabled
        and settings.govbr_client_id
        and settings.govbr_client_secret
    )


def new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


async def fetch_userinfo(token: dict) -> dict:
    """Busca o /userinfo do gov.br. Retorna JWT decodificado OU JSON puro."""
    meta = await oauth.govbr.load_server_metadata()
    endpoint = meta["userinfo_endpoint"]
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            endpoint,
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
    resp.raise_for_status()
    ctype = resp.headers.get("content-type", "")
    if "application/jwt" in ctype or resp.text.count(".") == 2:
        # userinfo assinado (JWT) - lê o payload sem validar assinatura aqui,
        # a confiança vem do canal TLS + token trocado server-to-server.
        payload_b64 = resp.text.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        import json

        return json.loads(base64.urlsafe_b64decode(payload_b64))
    return resp.json()
