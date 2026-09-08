from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL_OVERRIDE",
    f"sqlite:///{Path(tempfile.gettempdir()) / 'central_comando_test.db'}",
)
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("AUTO_CREATE_TABLES", "false")
# força federações desligadas nos testes (ignora o .env local) — nada de rede
os.environ["GOVBR_ENABLED"] = "false"
os.environ["LOGINUNICO_ENABLED"] = "false"
os.environ["MICROSOFT_CLIENT_ID"] = ""
os.environ["MICROSOFT_CLIENT_SECRET"] = ""
os.environ["MICROSOFT_TENANT_ID"] = ""

# limpa o db de teste antigo
_db = Path(tempfile.gettempdir()) / "central_comando_test.db"
if _db.exists():
    _db.unlink()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from scripts.seed import seed  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_client(client):
    resp = client.post(
        "/login",
        data={"identifier": "admin", "password": "admin123", "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.text
    return client
