from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_jwt
from app.database import get_db
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)


class RedirectToLogin(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


# --------------------------------------------------------------------------- #
# Web (sessão via cookie assinado)
# --------------------------------------------------------------------------- #
def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    user = db.get(User, uid)
    if user is None or not user.is_active:
        request.session.clear()
        return None
    return user


def require_web_user(
    request: Request, user: User | None = Depends(get_current_user_optional)
) -> User:
    if user is None:
        raise RedirectToLogin(next_url=str(request.url))
    return user


def require_web_admin(user: User = Depends(require_web_user)) -> User:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso restrito.")
    return user


# --------------------------------------------------------------------------- #
# API (Bearer JWT emitido pelo APP CENTRAL)
# --------------------------------------------------------------------------- #
def get_api_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ausente.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_jwt(creds.credentials)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token inválido: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("token_use") not in (None, "access"):
        raise HTTPException(status_code=401, detail="Tipo de token inválido.")

    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário inativo.")
    return user


def require_api_admin(user: User = Depends(get_api_user)) -> User:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requer admin.")
    return user
