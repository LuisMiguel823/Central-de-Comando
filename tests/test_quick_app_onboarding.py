from __future__ import annotations

import re

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Application, AuditEvent, Permission


def _create(admin_client, name="Sistema Teste Rapido", **extra):
    data = {"name": name, "redirect_uris": "https://x.example.com/auth/central/callback", **extra}
    return admin_client.post("/apps", data=data, follow_redirects=False)


def _package(page_html: str) -> str:
    m = re.search(r'<textarea id="integration-package"[^>]*>(.*?)</textarea>', page_html, re.S)
    assert m, "pacote de integração não apareceu"
    return m.group(1).replace("&#34;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")


def test_quick_create_generates_slug_and_shows_package(admin_client):
    r = _create(admin_client, name="Sistema Teste Rápido")
    assert r.status_code == 302
    slug = r.headers["location"].rsplit("/", 1)[1]
    assert slug == "sistema-teste-rapido"

    page = admin_client.get(r.headers["location"])
    assert page.status_code == 200
    pkg = _package(page.text)
    db = SessionLocal()
    try:
        a = db.scalar(select(Application).where(Application.slug == slug))
        assert a.oauth_client_id in pkg
        assert "client_secret: " in pkg and "{CLIENT_SECRET}" not in pkg
        assert "/api/v1/apps/permissions/sync" in pkg
        assert "https://x.example.com/auth/central/callback" in pkg
        assert "{BASE_URL_CENTRAL}" not in pkg and "{NAME}" not in pkg
    finally:
        db.close()

    # o segredo aparece uma única vez
    assert "integration-package" not in admin_client.get(r.headers["location"]).text

    # segundo sistema com o mesmo nome ganha sufixo
    r2 = _create(admin_client, name="Sistema Teste Rápido")
    assert r2.headers["location"].endswith("/sistema-teste-rapido-2")


def test_multi_client_flag_adds_tenant_instructions(admin_client):
    plain = _create(admin_client, name="Sistema Plain Um")
    pkg_plain = _package(admin_client.get(plain.headers["location"]).text)
    multi = _create(admin_client, name="Sistema Multi Um", multi_client="on")
    pkg_multi = _package(admin_client.get(multi.headers["location"]).text)
    assert "MULTI-CLIENTE (este sistema" not in pkg_plain
    assert "MULTI-CLIENTE (este sistema" in pkg_multi


def _creds(admin_client, name):
    r = _create(admin_client, name=name)
    pkg = _package(admin_client.get(r.headers["location"]).text)
    cid = re.search(r"client_id: (\S+)", pkg).group(1)
    secret = re.search(r"client_secret: (\S+)", pkg).group(1)
    return r.headers["location"].rsplit("/", 1)[1], cid, secret


def test_sync_permissions_creates_updates_and_never_deletes(admin_client):
    slug, cid, secret = _creds(admin_client, "Sistema Sync Um")
    anon = TestClient(app)

    body = {
        "client_id": cid,
        "client_secret": secret,
        "permissions": [
            {"code": "contratos.assinar", "name": "Assinar contratos", "description": "Libera"},
            {"code": "Contratos.Ver"},  # normaliza p/ minúsculas; nome cai no code
        ],
    }
    r = anon.post("/api/v1/apps/permissions/sync", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 2 and r.json()["updated"] == 0

    # idempotente
    again = anon.post("/api/v1/apps/permissions/sync", json=body).json()
    assert again["created"] == 0 and again["updated"] == 0 and again["unchanged"] == 2

    # atualiza nome; e uma chamada com lista menor NÃO apaga a outra
    body["permissions"] = [{"code": "contratos.assinar", "name": "Assinar contrato digital"}]
    upd = anon.post("/api/v1/apps/permissions/sync", json=body).json()
    assert upd["updated"] == 1 and upd["total_in_catalog"] == 2

    db = SessionLocal()
    try:
        a = db.scalar(select(Application).where(Application.slug == slug))
        codes = {p.code: p.name for p in db.scalars(select(Permission).where(Permission.application_id == a.id))}
        assert codes == {"contratos.assinar": "Assinar contrato digital", "contratos.ver": "contratos.ver"}
        assert "permission.sync_api" in db.scalars(select(AuditEvent.action)).all()
    finally:
        db.close()


def test_sync_permissions_rejects_bad_credentials_and_codes(admin_client):
    slug, cid, secret = _creds(admin_client, "Sistema Sync Dois")
    anon = TestClient(app)
    good = [{"code": "a.b"}]
    assert anon.post("/api/v1/apps/permissions/sync", json={"client_id": cid, "client_secret": "errado", "permissions": good}).status_code == 401
    assert anon.post("/api/v1/apps/permissions/sync", json={"client_id": "nao-existe", "client_secret": secret, "permissions": good}).status_code == 401
    bad = anon.post("/api/v1/apps/permissions/sync", json={"client_id": cid, "client_secret": secret, "permissions": [{"code": "tem espaço"}]})
    assert bad.status_code == 400
    # nada foi criado pelos pedidos rejeitados
    db = SessionLocal()
    try:
        a = db.scalar(select(Application).where(Application.slug == slug))
        assert db.scalars(select(Permission).where(Permission.application_id == a.id)).first() is None
    finally:
        db.close()


def test_sync_access_creates_users_grants_and_never_revokes(admin_client):
    from app.models import User, UserAppPermission

    slug, cid, secret = _creds(admin_client, "Sistema Acesso Um")
    anon = TestClient(app)
    body = {
        "client_id": cid,
        "client_secret": secret,
        "users": [
            {"email": "Maria@Empresa.com", "full_name": "Maria", "permissions": ["faq.editar", "faq.ver"]},
            {"email": "invalido", "permissions": ["faq.ver"]},
        ],
    }
    r = anon.post("/api/v1/apps/access/sync", json=body)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["users_created"] == 1 and j["grants_added"] == 2 and j["skipped_invalid_email"] == ["invalido"]

    again = anon.post("/api/v1/apps/access/sync", json=body).json()
    assert again["users_created"] == 0 and again["grants_added"] == 0

    # lista menor não revoga o que já foi concedido
    body["users"] = [{"email": "maria@empresa.com", "permissions": ["faq.ver"]}]
    anon.post("/api/v1/apps/access/sync", json=body)

    db = SessionLocal()
    try:
        u = db.scalar(select(User).where(User.email == "maria@empresa.com"))
        assert u is not None and u.password_hash is None
        assert len(db.scalars(select(UserAppPermission).where(UserAppPermission.user_id == u.id)).all()) == 2
    finally:
        db.close()

    bad = anon.post("/api/v1/apps/access/sync", json={**body, "client_secret": "errado"})
    assert bad.status_code == 401


def test_profile_fields_shape_the_single_prompt(admin_client):
    r = _create(
        admin_client, name="Sistema Perfil Um", base_url="https://perfil.example.com",
        stack="django", description="Base de conhecimento",
    )  # sem has_local_access marcado
    pkg = _package(admin_client.get(r.headers["location"]).text)
    assert "Django (Python)" in pkg
    assert "https://perfil.example.com" in pkg and "Base de conhecimento" in pkg
    assert "NÃO se aplica" in pkg or "NÃO SE APLICA" in pkg
    assert "/api/v1/apps/integration/report" in pkg
    assert "Entrar com outra conta" in pkg and "prompt=login" in pkg
    assert "FASE 1" in pkg and "FASE 2" in pkg

    r2 = _create(admin_client, name="Sistema Perfil Dois", has_local_access="on")
    pkg2 = _package(admin_client.get(r2.headers["location"]).text)
    assert "/api/v1/apps/access/sync" in pkg2 and "NÃO SE APLICA" not in pkg2


def test_integration_report_is_stored_and_shown(admin_client):
    slug, cid, secret = _creds(admin_client, "Sistema Relatorio Um")
    anon = TestClient(app)
    body = {
        "client_id": cid, "client_secret": secret, "status": "partial",
        "permissions": ["a.b"], "login_done": True, "switch_account_link": True,
        "central_requests": ["cadastrar https://x/cb2/"], "notes": "ok",
    }
    assert anon.post("/api/v1/apps/integration/report", json={**body, "client_secret": "x"}).status_code == 401
    r = anon.post("/api/v1/apps/integration/report", json=body)
    assert r.status_code == 200 and r.json()["central_requests"] == 1

    page = admin_client.get(f"/apps/{slug}").text
    assert "cadastrar https://x/cb2/" in page
    assert "Relatório do sistema" in page and "parcial" in page
