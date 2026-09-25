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


def test_authorize_without_session_keeps_full_query_through_login(client, oidc_app):
    """Regressão: deslogado -> /login -> volta pro /authorize COM todos os parâmetros."""
    params = {
        "response_type": "code",
        "client_id": oidc_app["client_id"],
        "redirect_uri": REDIRECT,
        "scope": "openid profile email",
        "state": "abc&x=1",  # caracteres que quebrariam um next mal codificado
        "code_challenge": "h1yEAkgH6cMNBrj3v8Ep5wciVHZDsvLHcW1Yiolmx34",
        "code_challenge_method": "S256",
    }
    r = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert r.status_code == 302
    login_url = urlparse(r.headers["location"])
    assert login_url.path == "/login"
    nxt = parse_qs(login_url.query)["next"][0]
    assert parse_qs(urlparse(nxt).query)["redirect_uri"] == [REDIRECT]

    r = client.post(
        "/login",
        data={"identifier": "admin", "password": "admin123", "next": nxt},
        follow_redirects=False,
    )
    assert r.status_code == 302
    back = urlparse(r.headers["location"])
    assert back.path == "/oauth/authorize"
    q = parse_qs(back.query)
    for key, value in params.items():
        assert q[key] == [value], key

    # já logado, o /authorize entrega o code de verdade
    r = client.get(r.headers["location"], follow_redirects=False)
    assert r.status_code == 302
    final = urlparse(r.headers["location"])
    assert f"{final.scheme}://{final.netloc}{final.path}" == REDIRECT
    assert parse_qs(final.query)["state"] == ["abc&x=1"]
    assert "code" in parse_qs(final.query)


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
