"""APP CENTRAL como provedor OIDC para os apps satélite (APP 1, 2, 3...)."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import create_jwt, generate_token, utcnow
from app.models import Application, OAuthToken, User, UserAppClient
from app.services.permissions import permissions_for


def userinfo_claims(db: Session, user: User, app: Application, scope: str) -> dict:
    scopes = set(scope.split())
    claims: dict = {"sub": str(user.id)}
    if "profile" in scopes:
        claims.update(
            {
                "name": user.full_name,
                "preferred_username": user.username,
                "updated_at": int(user.updated_at.timestamp()),
            }
        )
    if "email" in scopes:
        claims.update({"email": user.email, "email_verified": True})
    # permissões do usuário no app que pediu o token
    claims["permissions"] = permissions_for(db, user, app)
    claims["roles"] = ["superuser"] if user.is_superuser else []
    client = effective_client(db, user, app)
    if client is not None:
        claims["client_id"] = client.id
        claims["client_code"] = client.code
    return claims


def effective_client(db: Session, user: User, app: Application):
    """Cliente do usuário NESTE sistema: o vínculo configurado na página do
    sistema tem prioridade; sem ele, cai no cliente do cadastro geral (se houver)."""
    per_app = db.scalar(
        select(UserAppClient).where(
            UserAppClient.user_id == user.id, UserAppClient.application_id == app.id
        )
    )
    if per_app is not None:
        return per_app.client
    return user.client


def build_id_token(
    db: Session,
    user: User,
    app: Application,
    scope: str,
    *,
    nonce: str | None,
    access_token: str | None = None,
) -> str:
    claims = userinfo_claims(db, user, app, scope)
    claims["token_use"] = "id"
    if nonce:
        claims["nonce"] = nonce
    if access_token:
        digest = hashlib.sha256(access_token.encode()).digest()
        claims["at_hash"] = (
            base64.urlsafe_b64encode(digest[: len(digest) // 2]).decode().rstrip("=")
        )
    return create_jwt(claims, settings.access_token_ttl, audience=app.oauth_client_id)


def issue_token_set(
    db: Session,
    user: User,
    app: Application,
    scope: str,
    *,
    nonce: str | None = None,
    with_refresh: bool = True,
) -> dict:
    access = create_jwt(
        {
            "sub": str(user.id),
            "token_use": "access",
            "scope": scope,
            "azp": app.oauth_client_id,
        },
        settings.access_token_ttl,
        audience=app.oauth_client_id,
    )
    from app.core.security import decode_jwt

    jti = decode_jwt(access, audience=app.oauth_client_id)["jti"]

    now = utcnow()
    refresh = generate_token(48) if with_refresh else None
    db.add(
        OAuthToken(
            access_token_jti=jti,
            refresh_token=refresh,
            user_id=user.id,
            application_id=app.id,
            scope=scope,
            expires_at=now + timedelta(seconds=settings.access_token_ttl),
            refresh_expires_at=(
                now + timedelta(seconds=settings.refresh_token_ttl) if refresh else None
            ),
        )
    )
    db.flush()

    out = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl,
        "scope": scope,
        "id_token": build_id_token(db, user, app, scope, nonce=nonce, access_token=access),
    }
    if refresh:
        out["refresh_token"] = refresh
    return out


def verify_pkce(code_verifier: str, challenge: str, method: str | None) -> bool:
    if not challenge:
        return True
    if (method or "plain").lower() == "plain":
        return secrets.compare_digest(code_verifier, challenge)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return secrets.compare_digest(computed, challenge)


def discovery_document() -> dict:
    iss = settings.issuer
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "userinfo_endpoint": f"{iss}/oauth/userinfo",
        "jwks_uri": f"{iss}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": [
            "sub",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "permissions",
            "roles",
            "client_code",
        ],
    }
