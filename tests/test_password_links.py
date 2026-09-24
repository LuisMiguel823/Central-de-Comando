from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import utcnow, verify_password
from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, PasswordSetToken, User
from app.services import password_links as pl

LINK_RE = re.compile(r"/definir-senha/([A-Za-z0-9_\-]+)")


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    pl.reset_rate_limit()
    yield
    pl.reset_rate_limit()


def _import_one(admin_client, email):
    payload = json.dumps({"app_slug": "app-1", "users": [{"email": email, "full_name": "Pessoa Link"}]})
    r = admin_client.post("/operadores/importar/confirmar", data={"spec_json": payload})
    assert r.status_code == 200
    return r


def test_import_shows_link_once_and_stores_only_hash(admin_client):
    r = _import_one(admin_client, "link.um@x.com")
    assert "Baixar CSV" in r.text and "não serão mostrados de novo" in r.text
    token = LINK_RE.search(r.text).group(1)

    db = SessionLocal()
    try:
        rows = db.scalars(select(PasswordSetToken)).all()
        assert all(token not in row.token_hash and len(row.token_hash) == 64 for row in rows)
        u = db.scalar(select(User).where(User.email == "link.um@x.com"))
        assert u.password_hash is None
        acts = db.scalars(select(AuditEvent.action)).all()
        assert "user.password_link_created" in acts
    finally:
        db.close()


def test_set_password_flow_single_use_and_login(admin_client):
    token = LINK_RE.search(_import_one(admin_client, "link.dois@x.com").text).group(1)
    anon = TestClient(app)

    assert anon.get(f"/definir-senha/{token}").status_code == 200
    # validações
    assert anon.post(f"/definir-senha/{token}", data={"password": "curta", "confirm": "curta"}).status_code == 400
    assert "não conferem" in anon.post(f"/definir-senha/{token}", data={"password": "senhaforte1", "confirm": "outra1234"}).text
    ok = anon.post(f"/definir-senha/{token}", data={"password": "senhaforte1", "confirm": "senhaforte1"})
    assert ok.status_code == 200 and "Senha definida" in ok.text

    # uso único
    assert anon.get(f"/definir-senha/{token}").status_code == 404
    assert anon.post(f"/definir-senha/{token}", data={"password": "senhaforte2", "confirm": "senhaforte2"}).status_code == 404

    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.email == "link.dois@x.com"))
        assert verify_password("senhaforte1", u.password_hash)
    finally:
        db.close()
    # e o login funciona
    login = anon.post("/login", data={"identifier": "link.dois@x.com", "password": "senhaforte1", "next": "/"}, follow_redirects=False)
    assert login.status_code == 302


def test_expired_and_regenerated_links_die(admin_client):
    token = LINK_RE.search(_import_one(admin_client, "link.tres@x.com").text).group(1)
    anon = TestClient(app)

    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.email == "link.tres@x.com"))
        uid = u.id
        row = db.scalar(select(PasswordSetToken).where(PasswordSetToken.user_id == uid))
        row.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    assert anon.get(f"/definir-senha/{token}").status_code == 404  # expirado

    # admin gera link novo pelo botão avulso: só o novo vale
    r = admin_client.post(f"/operadores/{uid}/link-senha")
    assert r.status_code == 200 and "não será mostrado de novo" in r.text
    new_token = LINK_RE.search(r.text).group(1)
    assert new_token != token
    assert anon.get(f"/definir-senha/{new_token}").status_code == 200


def test_rate_limit_and_admin_only(admin_client):
    anon = TestClient(app)
    codes = [anon.get("/definir-senha/token-invalido").status_code for _ in range(25)]
    assert 429 in codes and codes[0] == 404
    # gerar link avulso exige admin
    assert TestClient(app).post("/operadores/1/link-senha", follow_redirects=False).status_code == 302
