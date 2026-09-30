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


def test_app_module_page_loads_and_importar_route_not_shadowed(admin_client):
    # /apps/importar é uma rota literal e precisa continuar acessível mesmo
    # com /apps/{slug} registrada (regressão: {slug} "engolindo" "importar").
    r = admin_client.get("/apps/importar")
    assert r.status_code == 200
    assert "spec_json" in r.text or "Importar" in r.text

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
    # página tem que continuar dando pra ver mesmo assim — mas sem a chave,
    # não pode vazar host/usuário/erro do driver pra qualquer visitante.
    r = client.get("/status")
    assert r.status_code == 200
    assert "Banco de dados OK" in r.text
    from app.config import settings

    assert settings.db_user not in r.text
    assert settings.db_host not in r.text
    assert f":{settings.db_password}@" not in r.text


def test_status_page_with_key_shows_target_but_never_password(client):
    from app.config import settings
    from app.main import _status_key

    r = client.get(f"/status?key={_status_key()}")
    assert r.status_code == 200
    expected_target = f"{settings.db_user}@{settings.db_host}:{settings.db_port}/{settings.db_name}"
    assert expected_target in r.text
    assert f":{settings.db_password}@" not in r.text


def test_status_page_rejects_wrong_key(client):
    from app.config import settings

    r = client.get("/status?key=chave-errada")
    assert r.status_code == 200
    assert settings.db_host not in r.text
