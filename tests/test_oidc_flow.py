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
    # admin da Central NÃO herda permissões dos sistemas: só o que foi concedido
    assert info["permissions"] == [] and info["roles"] == []

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
    assert r.json()["permissions"] == [] and "is_superuser" not in r.json()

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


def test_authorize_prompt_login_forces_credentials(admin_client, oidc_app):
    params = {
        "response_type": "code",
        "client_id": oidc_app["client_id"],
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "xyz",
    }
    # admin já logado: com prompt=login NÃO entrega o code, pede login de novo
    r = admin_client.get(
        "/oauth/authorize", params={**params, "prompt": "login", "max_age": "0"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "prompt" not in r.headers["location"] and "max_age" not in r.headers["location"]
    r = admin_client.get(r.headers["location"], follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login?next=")


def test_integration_package_mentions_switch_account():
    from app.core.prompts import build_integration_package

    pkg = build_integration_package(
        name="X", client_id="c", client_secret="s", central_url="https://c.example",
        redirect_uris="https://x/cb", multi_client=False,
    )
    assert "Entrar com outra conta" in pkg and "prompt=login" in pkg


def test_authorize_tolerates_trailing_slash(admin_client, oidc_app):
    r = admin_client.get(
        "/oauth/authorize",
        params={"response_type": "code", "client_id": oidc_app["client_id"],
                "redirect_uri": REDIRECT + "/", "scope": "openid"},
        follow_redirects=False,
    )
    assert r.status_code == 302 and r.headers["location"].startswith(REDIRECT + "/?code=")


def test_central_admin_only_sees_systems_it_was_granted(admin_client, oidc_app):
    """Admin da Central é admin só da Central: entra no sistema só depois de
    receber permissão ali, e só então aparece na lista de pessoas do módulo."""
    from sqlalchemy import select

    from app.models import Permission, User

    db = SessionLocal()
    try:
        admin = db.scalar(select(User).where(User.is_superuser.is_(True)))
        perm = db.scalar(select(Permission).where(
            Permission.application_id == oidc_app["id"], Permission.code == "teste.ler"))
        admin_email, perm_id, admin_id = admin.email, perm.id, admin.id
    finally:
        db.close()

    page = admin_client.get("/apps/app-teste-oidc").text
    assert f'<option value="{admin_id}">' in page  # admin é candidato, não membro
    assert f'<span class="acc-mail">{admin_email}</span>' not in page

    r = admin_client.post(
        f"/apps/{oidc_app['id']}/usuarios/adicionar",
        data={"user_id": admin_id, "permission_id": perm_id}, follow_redirects=False,
    )
    assert r.status_code == 302

    page = admin_client.get("/apps/app-teste-oidc").text
    assert f'<option value="{admin_id}">' not in page  # agora é membro
    assert f'<span class="acc-mail">{admin_email}</span>' in page

    from app.models import Application
    from app.services import oidc

    db = SessionLocal()
    try:
        claims = oidc.userinfo_claims(
            db, db.get(User, admin_id), db.get(Application, oidc_app["id"]), "openid")
        assert claims["permissions"] == ["teste.ler"] and claims["roles"] == []
    finally:
        db.close()
