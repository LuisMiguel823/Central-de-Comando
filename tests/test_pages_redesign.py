from __future__ import annotations

import json
from datetime import datetime, timedelta

from app.core.templating import ago, initials, module_hue


def _make_user(admin_client, email, name="Pessoa Filtro"):
    payload = json.dumps({"app_slug": "app-1", "users": [{"email": email, "full_name": name}]})
    assert admin_client.post("/operadores/importar/confirmar", data={"spec_json": payload}).status_code == 200


# ----------------------------------------------------------------- filtros
def test_ago_formats():
    now = datetime(2026, 10, 5, 12, 0, 0)
    assert ago(None, now) == "—"
    assert ago(now - timedelta(seconds=10), now) == "agora"
    assert ago(now - timedelta(minutes=5), now) == "há 5 min"
    assert ago(now - timedelta(hours=3), now) == "há 3 h"
    assert ago(now - timedelta(days=2), now) == "há 2 d"
    assert ago(now - timedelta(days=30), now) == "05/09/2026"


def test_module_hue_is_stable_and_initials():
    assert module_hue("regula-rpps") == module_hue("regula-rpps")
    assert len(module_hue("x").split()) == 3
    assert initials("Regula RPPS") == "RR"
    assert initials("milvus") == "MI"
    assert initials("") == "?"


# --------------------------------------------------------------- dashboard
def test_dashboard_has_hero_cards_and_no_old_prompts(admin_client):
    r = admin_client.get("/")
    assert r.status_code == 200
    for label in ("Sistemas integrados", "Usuários ativos", "Acessos hoje", "Falhas de login"):
        assert label in r.text
    assert r.text.count('class="hero-slot"') == 4
    assert "Atividade recente" in r.text and "Atalhos" in r.text
    # prompts do fluxo antigo saíram
    assert "Prompt de descoberta" not in r.text
    assert "prompt-implementation" not in r.text


# ----------------------------------------------------------------- sistemas
def test_systems_page_shows_module_tiles_without_inner_content(admin_client):
    r = admin_client.get("/apps")
    assert r.status_code == 200
    assert 'class="mod-tile' in r.text and "Entrar no módulo" in r.text
    assert "Importar especificação" not in r.text
    # o conteúdo do sistema (permissões/usuários) só aparece dentro do módulo
    assert "usuário(s) com acesso" not in r.text
    inner = admin_client.get("/apps/app-1")
    assert 'class="mod-hero' in inner.text and "Catálogo de permissões" in inner.text


# ----------------------------------------------------------------- usuários
def test_users_page_filters_and_cards(admin_client):
    _make_user(admin_client, "filtro.um@x.com")
    r = admin_client.get("/operadores")
    assert r.status_code == 200
    assert 'class="person-card' in r.text and "filter-pill" in r.text

    # recém-importado ainda não definiu senha -> aparece no filtro "sem senha"
    sem = admin_client.get("/operadores?f=semsenha")
    assert "filtro.um@x.com" in sem.text
    admins = admin_client.get("/operadores?f=admins")
    assert "filtro.um@x.com" not in admins.text

    # filtro desconhecido cai em "todos"; busca sem resultado mostra o estado vazio
    assert "filtro.um@x.com" in admin_client.get("/operadores?f=xyz").text
    vazio = admin_client.get("/operadores?q=nada-disso-existe")
    assert "Nenhum usuário encontrado" in vazio.text
