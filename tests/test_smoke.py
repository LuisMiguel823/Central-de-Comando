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
