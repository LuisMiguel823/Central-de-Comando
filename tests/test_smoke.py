from __future__ import annotations


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_page(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "Entrar" in r.text


def test_dashboard_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["location"]


def test_dashboard_after_login(admin_client):
    r = admin_client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text


def test_crud_pages_load(admin_client):
    for path in ("/clientes", "/operadores", "/apps", "/auditoria", "/sobre"):
        assert admin_client.get(path).status_code == 200


def test_app_module_page_loads(admin_client):
    # o importador de especificação JSON foi removido: a rota antiga cai na
    # genérica /apps/{slug} e dá 404 (nenhum sistema com esse slug).
    assert admin_client.get("/apps/importar").status_code == 404

    r = admin_client.get("/apps/app-1")
    assert r.status_code == 200
    assert "Protocolo Digital" in r.text

    r = admin_client.get("/apps/nao-existe-esse-slug")
    assert r.status_code == 404


def test_discovery(client):
    r = client.get("/.well-known/openid-configuration")
    assert r.status_code == 200
    body = r.json()
    assert body["token_endpoint"].endswith("/oauth/token")
    assert "authorization_code" in body["grant_types_supported"]


def test_jwks(client):
    r = client.get("/oauth/jwks.json")
    assert r.status_code == 200
    assert r.json()["keys"][0]["kty"] == "RSA"


def test_audit_recorded_on_login(admin_client):
    r = admin_client.get("/auditoria")
    assert "auth.login" in r.text


def test_status_page_public_view_hides_infra_details(client):
    # sem login de propósito: se o banco cair, o login também cai, e essa
    # página tem que continuar dando pra ver mesmo assim — mas sem estar
    # logado como admin, não pode vazar host/usuário/erro do driver pra
    # qualquer visitante.
    r = client.get("/status")
    assert r.status_code == 200
    assert "Banco de dados OK" in r.text
    from app.config import settings

    assert settings.db_user not in r.text
    assert settings.db_host not in r.text
    assert f":{settings.db_password}@" not in r.text


def test_status_page_shows_target_to_logged_admin_but_never_password(admin_client):
    from app.config import settings

    r = admin_client.get("/status")
    assert r.status_code == 200
    expected_target = f"{settings.db_user}@{settings.db_host}:{settings.db_port}/{settings.db_name}"
    assert expected_target in r.text
    assert f":{settings.db_password}@" not in r.text
