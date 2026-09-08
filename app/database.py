from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings

_url = settings.database_url

if _url.startswith("sqlite"):
    engine = create_engine(
        _url,
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(
        _url,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """Dependência FastAPI: uma sessão por request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    # importa todos os modelos para registrar no metadata
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
