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
    assert "Módulos" in home.text and "https://sistema-um.exemplo.com" in home.text
    assert "OPX1" in home.text
    # nada de dados globais da Central na home nem no menu
    assert "Usuários ativos" not in home.text and 'href="/operadores"' not in home.text

    for path in ("/operadores", "/clientes", "/apps", "/apps/app-1", "/auditoria", "/sobre"):
        assert c.get(path).status_code == 403, path


def test_modules_page_and_end_session_logout():
    db = SessionLocal()
    try:
        seeded = db.scalar(select(User).where(User.username == "op.comum")) is not None
    finally:
        db.close()
    if not seeded:  # o banco de teste é compartilhado com o teste acima
        _seed_operator()
    c = TestClient(app)
    c.post("/login", data={"identifier": "op.comum", "password": "senha12345"}, follow_redirects=False)

    mods = c.get("/modulos")
    assert mods.status_code == 200 and "https://sistema-um.exemplo.com" in mods.text

    # destino não cadastrado nunca é aceito (anti open-redirect): cai no login da Central
    r = c.get("/oauth/logout?post_logout_redirect_uri=https://malicioso.exemplo.net/x", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    assert c.get("/modulos", follow_redirects=False).status_code in (302, 401)

    # destino de um sistema cadastrado é aceito
    c.post("/login", data={"identifier": "op.comum", "password": "senha12345"}, follow_redirects=False)
    r = c.get("/oauth/logout?post_logout_redirect_uri=https://sistema-um.exemplo.com/login", follow_redirects=False)
    assert r.headers["location"] == "https://sistema-um.exemplo.com/login"


def test_require_access_gate_blocks_user_without_permission():
    from urllib.parse import urlencode

    db = SessionLocal()
    try:
        if db.scalar(select(User).where(User.username == "op.comum")) is None:
            _seed_operator()
        app1 = db.scalar(select(Application).where(Application.slug == "app-1"))
        cid, redirect = app1.oauth_client_id, app1.redirect_uri_list[0]
        if db.scalar(select(User).where(User.username == "sem.acesso")) is None:
            db.add(User(username="sem.acesso", email="sem.acesso@x.com", full_name="Sem Acesso",
                        password_hash=hash_password("senha12345")))
        app1.require_access = True
        db.commit()
    finally:
        db.close()

    qs = urlencode({"response_type": "code", "client_id": cid, "redirect_uri": redirect, "state": "s"})
    try:
        blocked = TestClient(app)
        blocked.post("/login", data={"identifier": "sem.acesso", "password": "senha12345"}, follow_redirects=False)
        r = blocked.get(f"/oauth/authorize?{qs}", follow_redirects=False)
        assert r.status_code == 403 and "não tem acesso" in r.text

        allowed = TestClient(app)
        allowed.post("/login", data={"identifier": "op.comum", "password": "senha12345"}, follow_redirects=False)
        r = allowed.get(f"/oauth/authorize?{qs}", follow_redirects=False)
        assert r.status_code == 302 and "code=" in r.headers["location"]
    finally:
        db = SessionLocal()
        try:
            db.scalar(select(Application).where(Application.slug == "app-1")).require_access = False
            db.commit()
        finally:
            db.close()


def test_module_flow_package_on_app_page_has_no_secret(admin_client):
    r = admin_client.get("/apps/app-1")
    assert r.status_code == 200
    assert "Fluxo de módulo" in r.text and "/oauth/logout" in r.text
    assert "client_secret" in r.text and "&lt;do ambiente&gt;" in r.text  # placeholder, nunca o segredo
