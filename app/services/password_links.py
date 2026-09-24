"""Links de uso único pra o usuário definir a própria senha (sem SMTP).

- O token é aleatório (256 bits) e só o hash SHA-256 fica no banco: quem gera
  vê o link UMA vez; depois só dá pra gerar outro (o anterior é apagado).
- Expira (PASSWORD_LINK_TTL_HOURS) e morre no primeiro uso.
- Geração e uso são registrados na auditoria (sem nunca logar o token).
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import settings
from app.core import audit
from app.core.security import hash_password, utcnow
from app.models import PasswordSetToken, User

MIN_LEN = 8
MAX_BYTES = 72  # limite do bcrypt


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_link(
    db: Session, user: User, *, actor: User, request=None
) -> tuple[str, datetime]:
    """Cria (e devolve) um link novo; apaga os anteriores ainda não usados."""
    db.execute(
        delete(PasswordSetToken).where(
            PasswordSetToken.user_id == user.id, PasswordSetToken.used_at.is_(None)
        )
    )
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(hours=settings.password_link_ttl_hours)
    db.add(
        PasswordSetToken(
            user_id=user.id,
            token_hash=_hash(token),
            expires_at=expires,
            created_by_id=actor.id,
        )
    )
    audit.record(
        db,
        "user.password_link_created",
        actor=actor,
        target_type="user",
        target_id=user.id,
        description=f"Gerou link de definição de senha para {user.username}",
        request=request,
        meta={"expires_at": expires.isoformat()},
        commit=False,
    )
    url = f"{settings.base_url.rstrip('/')}/definir-senha/{token}"
    return url, expires


def find_valid(db: Session, token: str) -> PasswordSetToken | None:
    if not token or len(token) > 200:
        return None
    row = db.scalar(select(PasswordSetToken).where(PasswordSetToken.token_hash == _hash(token)))
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return None
    return row


def validate_password(password: str, confirm: str) -> str | None:
    if len(password) < MIN_LEN:
        return f"A senha precisa ter pelo menos {MIN_LEN} caracteres."
    if len(password.encode()) > MAX_BYTES:
        return "A senha é longa demais (máximo 72 bytes)."
    if password != confirm:
        return "As senhas não conferem."
    return None


def consume(db: Session, row: PasswordSetToken, password: str, *, request=None) -> User:
    user = db.get(User, row.user_id)
    user.password_hash = hash_password(password)
    row.used_at = utcnow()
    # qualquer outro link pendente do mesmo usuário também morre
    db.execute(
        delete(PasswordSetToken).where(
            PasswordSetToken.user_id == user.id,
            PasswordSetToken.used_at.is_(None),
            PasswordSetToken.id != row.id,
        )
    )
    audit.record(
        db,
        "auth.password_set",
        actor=user,
        target_type="user",
        target_id=user.id,
        description="Definiu a própria senha via link",
        request=request,
        commit=False,
    )
    db.commit()
    return user


# ---- rate limit básico (por IP, em memória; 1 processo) ------------------- #
_WINDOW = 600  # 10 min
_MAX_HITS = 20
_hits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()


def rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > _WINDOW:
            q.popleft()
        if len(q) >= _MAX_HITS:
            return True
        q.append(now)
        return False


def reset_rate_limit() -> None:  # usado nos testes
    with _lock:
        _hits.clear()
