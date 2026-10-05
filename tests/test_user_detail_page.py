from __future__ import annotations

import json
import re

from sqlalchemy import select

from app.database import SessionLocal
from app.models import Application, Client, Permission, User, UserAppClient, UserAppPermission


def _make_user(admin_client, email):
    payload = json.dumps({"app_slug": "app-1", "users": [{"email": email, "full_name": "Pessoa Detalhe"}]})
    assert admin_client.post("/operadores/importar/confirmar", data={"spec_json": payload}).status_code == 200
    db = SessionLocal()
    try:
        return db.scalar(select(User).where(User.email == email)).id
    finally:
        db.close()


def test_list_shows_password_state_and_manage_link(admin_client):
    uid = _make_user(admin_client, "detalhe.lista@x.com")
    r = admin_client.get("/operadores")
    assert r.status_code == 200
    assert f'href="/operadores/{uid}"' in r.text
    assert "link enviado" in r.text  # importação já gerou o link pendente


def test_detail_tabs_render(admin_client):
    uid = _make_user(admin_client, "detalhe.abas@x.com")
    dados = admin_client.get(f"/operadores/{uid}")
    assert dados.status_code == 200 and "Salvar dados" in dados.text and "Excluir usuário" in dados.text
    acesso = admin_client.get(f"/operadores/{uid}?aba=acesso")
    assert "Gerar link de senha" in acesso.text and "Link enviado, aguardando" in acesso.text
    sistemas = admin_client.get(f"/operadores/{uid}?aba=sistemas")
    assert "Salvar permissões" in sistemas.text
    # aba inválida cai em Dados; usuário inexistente dá 404
    assert "Salvar dados" in admin_client.get(f"/operadores/{uid}?aba=xyz").text
    assert admin_client.get("/operadores/999999").status_code == 404


def test_old_permissions_url_redirects(admin_client):
    uid = _make_user(admin_client, "detalhe.redir@x.com")
    r = admin_client.get(f"/operadores/{uid}/permissoes", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == f"/operadores/{uid}?aba=sistemas"


def test_sistemas_tab_saves_permissions_and_client_per_app(admin_client):
    uid = _make_user(admin_client, "detalhe.salvar@x.com")
    db = SessionLocal()
    try:
        app = db.scalar(select(Application).where(Application.slug == "app-1"))
        perm = db.scalars(select(Permission).where(Permission.application_id == app.id)).first()
        client = db.scalars(select(Client)).first()
        app_id = app.id
        perm_id = perm.id if perm else None
        client_id = client.id if client else None
    finally:
        db.close()

    data = {f"client_app_{app_id}": str(client_id or "")}
    if perm_id:
        data["permission_id"] = str(perm_id)
    r = admin_client.post(f"/operadores/{uid}/permissoes", data=data, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == f"/operadores/{uid}?aba=sistemas"

    db = SessionLocal()
    try:
        if client_id:
            link = db.scalar(
                select(UserAppClient).where(
                    UserAppClient.user_id == uid, UserAppClient.application_id == app_id
                )
            )
            assert link is not None and link.client_id == client_id
        if perm_id:
            assert db.scalar(
                select(UserAppPermission).where(
                    UserAppPermission.user_id == uid, UserAppPermission.permission_id == perm_id
                )
            )
    finally:
        db.close()

    # limpar o cliente remove o vínculo
    admin_client.post(f"/operadores/{uid}/permissoes", data={f"client_app_{app_id}": ""})
    db = SessionLocal()
    try:
        assert db.scalar(
            select(UserAppClient).where(UserAppClient.user_id == uid)
        ) is None
    finally:
        db.close()


def test_delete_redirects_to_list(admin_client):
    uid = _make_user(admin_client, "detalhe.excluir@x.com")
    r = admin_client.post(
        f"/operadores/{uid}/excluir",
        headers={"referer": f"http://testserver/operadores/{uid}"},
        follow_redirects=False,
    )
    assert r.status_code == 302 and r.headers["location"] == "/operadores"


def test_apps_detail_no_longer_edits_identity(admin_client):
    _make_user(admin_client, "detalhe.apps@x.com")
    r = admin_client.get("/apps/app-1")
    assert r.status_code == 200
    assert "Excluir usuário" not in r.text and "Salvar dados" not in r.text
    assert re.search(r'href="/operadores/\d+"', r.text)
