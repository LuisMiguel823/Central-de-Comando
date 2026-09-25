from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.main import app
from app.models import Application, Client, ClientTier, Permission, User, UserAppClient, UserAppPermission


def _seed_operator():
    db = SessionLocal()
    try:
        app1 = db.scalar(select(Application).where(Application.slug == "app-1"))
        app1.base_url = "https://sistema-um.exemplo.com"
        perm = db.scalar(select(Permission).where(Permission.application_id == app1.id))
        cli = Client(code="OPX1", name="Cliente Operador", tier=ClientTier.BRONZE)
        u = User(username="op.comum", email="op.comum@x.com", full_name="Op Comum",
                 password_hash=hash_password("senha12345"))
        db.add_all([cli, u])
        db.flush()
        db.add(UserAppPermission(user_id=u.id, application_id=app1.id, permission_id=perm.id))
        db.add(UserAppClient(user_id=u.id, application_id=app1.id, client_id=cli.id))
        db.commit()
    finally:
        db.close()


def test_regular_operator_sees_only_own_systems_and_no_admin_pages():
    _seed_operator()
    c = TestClient(app)
    r = c.post("/login", data={"identifier": "op.comum", "password": "senha12345"}, follow_redirects=False)
    assert r.status_code == 302

    home = c.get("/")
    assert home.status_code == 200
    assert "Meus sistemas" in home.text and "https://sistema-um.exemplo.com" in home.text
    assert "OPX1" in home.text
    # nada de dados globais da Central na home nem no menu
    assert "Usuários ativos" not in home.text and 'href="/operadores"' not in home.text

    for path in ("/operadores", "/clientes", "/apps", "/apps/app-1", "/auditoria", "/sobre"):
        assert c.get(path).status_code == 403, path
