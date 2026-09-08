from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from app.core.security import generate_client_id, hash_password
from app.database import SessionLocal
from app.models import Application, Permission

REDIRECT = "https://app-teste.local/auth/callback"
SECRET = "segredo-de-teste-123"


@pytest.fixture(scope="module")
def oidc_app():
    db = SessionLocal()
    try:
        app = Application(
            name="App Teste OIDC",
            slug="app-teste-oidc",
            oauth_client_id=generate_client_id(),
            oauth_client_secret_hash=hash_password(SECRET),
            redirect_uris=REDIRECT,
            allowed_scopes="openid profile email",
        )
        db.add(app)
        db.flush()
        db.add(Permission(application_id=app.id, code="teste.ler", name="Ler"))
        db.add(Permission(application_id=app.id, code="teste.editar", name="Editar"))
        db.commit()
        db.refresh(app)
        return {"client_id": app.oauth_client_id, "id": app.id}
    finally:
        db.close()


def test_authorization_code_flow(admin_client, oidc_app):
    # 1) /authorize -> redireciona para o redirect_uri com ?code=
    r = admin_client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": oidc_app["client_id"],
            "redirect_uri": REDIRECT,
            "scope": "openid profile email",
            "state": "xyz",
            "nonce": "n-1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    loc = urlparse(r.headers["location"])
    qs = parse_qs(loc.query)
    assert qs["state"] == ["xyz"]
    code = qs["code"][0]

    # 2) /token
    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": oidc_app["client_id"],
            "client_secret": SECRET,
        },
    )
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["token_type"] == "Bearer"
    assert "access_token" in tok and "id_token" in tok and "refresh_token" in tok

    # 3) /userinfo
    r = admin_client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {tok['access_token']}"},
    )
    assert r.status_code == 200, r.text
    info = r.json()
    assert info["sub"]
    # admin herda todas as permissões do app
    assert set(info["permissions"]) == {"teste.ler", "teste.editar"}

    # 4) introspect
    r = admin_client.post(
        "/api/v1/introspect",
        data={
            "token": tok["access_token"],
            "client_id": oidc_app["client_id"],
            "client_secret": SECRET,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["active"] is True

    # 5) refresh_token
    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": oidc_app["client_id"],
            "client_secret": SECRET,
        },
    )
    assert r.status_code == 200, r.text
    assert "access_token" in r.json()


def test_authorize_rejects_unknown_redirect(admin_client, oidc_app):
    r = admin_client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": oidc_app["client_id"],
            "redirect_uri": "https://evil.example/cb",
            "scope": "openid",
        },
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_token_rejects_bad_secret(admin_client, oidc_app):
    r = admin_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": "whatever",
            "client_id": oidc_app["client_id"],
            "client_secret": "errado",
        },
    )
    assert r.status_code == 401
