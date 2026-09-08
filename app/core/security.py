from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "RS256"
KEY_ID = "central-comando-key-1"


# --------------------------------------------------------------------------- #
# Senhas
# --------------------------------------------------------------------------- #
def hash_password(raw: str) -> str:
    return pwd_context.hash(raw)


def verify_password(raw: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return pwd_context.verify(raw, hashed)
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Segredos genéricos
# --------------------------------------------------------------------------- #
def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def generate_client_id() -> str:
    return "app_" + secrets.token_hex(12)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(40)


# --------------------------------------------------------------------------- #
# Chaves RSA para assinar JWT (provedor OIDC)
# --------------------------------------------------------------------------- #
def _load_or_create_keys() -> tuple[str, str]:
    priv_path = Path(settings.jwt_private_key_path)
    pub_path = Path(settings.jwt_public_key_path)

    if priv_path.exists() and pub_path.exists():
        return priv_path.read_text(), pub_path.read_text()

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    priv_path.write_text(priv_pem)
    pub_path.write_text(pub_pem)
    return priv_pem, pub_pem


_PRIVATE_KEY, _PUBLIC_KEY = _load_or_create_keys()


def private_key() -> str:
    return _PRIVATE_KEY


def public_key() -> str:
    return _PUBLIC_KEY


def jwks() -> dict:
    from jose import jwk

    key_obj = jwk.construct(_PUBLIC_KEY, ALGORITHM).to_dict()
    key_obj.update({"use": "sig", "kid": KEY_ID, "alg": ALGORITHM})
    return {"keys": [key_obj]}


# --------------------------------------------------------------------------- #
# Emissão / verificação de JWT
# --------------------------------------------------------------------------- #
def create_jwt(claims: dict, ttl: int, *, audience: str | None = None) -> str:
    now = int(time.time())
    payload = {
        "iss": settings.issuer,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
        **claims,
    }
    if audience:
        payload["aud"] = audience
    return jwt.encode(
        payload, _PRIVATE_KEY, algorithm=ALGORITHM, headers={"kid": KEY_ID}
    )


def decode_jwt(token: str, *, audience: str | None = None) -> dict:
    return jwt.decode(
        token,
        _PUBLIC_KEY,
        algorithms=[ALGORITHM],
        audience=audience,
        issuer=settings.issuer,
        options={"verify_aud": audience is not None},
    )


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
