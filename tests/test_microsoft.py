from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import func, select

from app.config import settings
from app.database import SessionLocal
from app.models import User
from app.services import microsoft

TENANT = "00000000-1111-2222-3333-444444444444"
REDIRECT = "https://central.exemplo.gov.br/auth/microsoft/callback"


@pytest.fixture
def ms_enabled(monkeypatch):
    monkeypatch.setattr(settings, "microsoft_client_id", "client-abc")
    monkeypatch.setattr(settings, "microsoft_client_secret", "secret-xyz")
    monkeypatch.setattr(settings, "microsoft_tenant_id", TENANT)
    monkeypatch.setattr(settings, "microsoft_redirect_uri", REDIRECT)
    yield


def _do_login(client) -> str:
    """Chama /auth/microsoft/login e devolve o state gerado."""
    r = client.get("/auth/microsoft/login", params={"next": "/"}, follow_redirects=False)
    assert r.status_code == 302
    loc = urlparse(r.headers["location"])
    assert loc.netloc == "login.microsoftonline.com"
    assert loc.path == f"/{TENANT}/oauth2/v2.0/authorize"
    qs = parse_qs(loc.query)
    assert qs["client_id"] == ["client-abc"]
    assert qs["redirect_uri"] == [REDIRECT]
    assert qs["response_type"] == ["code"]
    assert "User.Read" in qs["scope"][0]
    return qs["state"][0]


def test_microsoft_login_builds_authorize_url(client, ms_enabled):
    state = _do_login(client)
    assert len(state) > 20


def test_microsoft_callback_existing_user_logs_in(client, ms_enabled, monkeypatch):
    state = _do_login(client)
    monkeypatch.setattr(microsoft, "_http_post", lambda url, data: {"access_token": "AT123"})
    monkeypatch.setattr(
        microsoft, "_http_get",
        lambda url, headers: {"mail": "admin@local", "userPrincipalName": "admin@local"},
    )
    r = client.get(
        "/auth/microsoft/callback",
        params={"code": "the-code", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"] == "/"
    assert client.get("/").status_code == 200  # sessão logada


def test_microsoft_callback_unknown_email_denied_and_no_provision(client, ms_enabled, monkeypatch):
    db = SessionLocal()
    before = db.scalar(select(func.count(User.id)))
    db.close()

    state = _do_login(client)
    monkeypatch.setattr(microsoft, "_http_post", lambda url, data: {"access_token": "AT"})
    monkeypatch.setattr(
        microsoft, "_http_get",
        lambda url, headers: {"mail": "desconhecido@fora.com"},
    )
    r = client.get(
        "/auth/microsoft/callback",
        params={"code": "c", "state": state},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "sem+cadastro" in r.headers["location"]
    # não logou
    assert client.get("/", follow_redirects=False).status_code == 302
    # não criou usuário
    db = SessionLocal()
    assert db.scalar(select(func.count(User.id))) == before
    db.close()


def test_microsoft_callback_bad_state_aborts(client, ms_enabled, monkeypatch):
    _do_login(client)
    monkeypatch.setattr(microsoft, "_http_post", lambda url, data: {"access_token": "AT"})
    monkeypatch.setattr(microsoft, "_http_get", lambda url, headers: {"mail": "admin@local"})
    r = client.get(
        "/auth/microsoft/callback",
        params={"code": "c", "state": "state-errado"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "inv%C3%A1lida" in r.headers["location"]
    assert client.get("/", follow_redirects=False).status_code == 302


def test_microsoft_callback_provider_error(client, ms_enabled):
    _do_login(client)
    r = client.get(
        "/auth/microsoft/callback",
        params={"error": "access_denied", "error_description": "user cancelled"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "Microsoft" in r.headers["location"]


def test_microsoft_disabled_redirects(client):
    r = client.get("/auth/microsoft/login", follow_redirects=False)
    assert r.status_code == 302
    assert "n%C3%A3o+configurado" in r.headers["location"]


def test_email_from_me():
    assert microsoft.email_from_me({"mail": "A@B.COM"}) == "a@b.com"
    assert microsoft.email_from_me({"mail": "", "userPrincipalName": "U@P.com"}) == "u@p.com"
    assert microsoft.email_from_me({}) is None
