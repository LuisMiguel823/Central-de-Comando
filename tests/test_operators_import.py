from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import Client, Permission, User, UserAppPermission
from app.services import operators_import as oi

APP = "app-1"  # criado pelo seed; catálogo tem protocolo.ler / protocolo.criar


def _spec(**over) -> dict:
    base = {
        "app_slug": APP,
        "clients": [{"code": "impx1", "name": "Prefeitura Import X", "city": "Cidade X"}],
        "users": [
            {
                "email": "Ana.Import@Exemplo.com",
                "full_name": "Ana Import",
                "client_code": "IMPX1",
                "permissions": ["protocolo.ler", "protocolo.criar", "nao.existe"],
            },
            {"email": "bia.import@exemplo.com", "full_name": "Bia Import",
             "client_code": "IMPX1", "permissions": ["protocolo.ler"]},
        ],
    }
    base.update(over)
    return base


class _Req:  # audit.record só lê client/headers se existirem
    client = None
    headers: dict = {}


@pytest.fixture
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def admin(db):
    return db.scalar(select(User).where(User.username == "admin"))


def _grants(db, email):
    u = db.scalar(select(User).where(User.email == email))
    return sorted(
        db.scalars(
            select(Permission.code)
            .join(UserAppPermission, UserAppPermission.permission_id == Permission.id)
            .where(UserAppPermission.user_id == u.id)
        ).all()
    )


def test_plan_is_read_only_and_flags_unknown_permission(db):
    before = db.scalar(select(func.count(User.id)))
    plan = oi.build_plan(db, oi.parse_spec(json.dumps(_spec())))
    assert db.scalar(select(func.count(User.id))) == before  # preview não grava
    assert plan.users_create == 2 and plan.clients_create == 1
    assert plan.grants_total == 3
    assert any("nao.existe" in w for w in plan.warnings)


def test_apply_then_idempotent_second_run(db, admin):
    spec = oi.parse_spec(json.dumps(_spec()))
    s1 = oi.apply_plan(db, oi.build_plan(db, spec), actor=admin, request=_Req())
    assert s1["users_created"] == 2 and s1["grants_added"] == 3 and s1["clients_created"] == 1

    ana = db.scalar(select(User).where(User.email == "ana.import@exemplo.com"))
    assert ana.password_hash is None and ana.is_active is True
    assert ana.client.code == "IMPX1"
    assert _grants(db, "ana.import@exemplo.com") == ["protocolo.criar", "protocolo.ler"]

    # segunda rodada: nada novo, nada duplicado
    plan2 = oi.build_plan(db, spec)
    assert plan2.users_create == 0 and plan2.clients_create == 0
    assert plan2.grants_total == 0 and plan2.users_unchanged == 2
    s2 = oi.apply_plan(db, plan2, actor=admin, request=_Req())
    assert s2["users_created"] == 0 and s2["grants_added"] == 0
    assert db.scalar(select(func.count(Client.id)).where(Client.code == "IMPX1")) == 1


def test_never_removes_permissions_and_never_reactivates_or_demotes(db, admin):
    oi.apply_plan(db, oi.build_plan(db, oi.parse_spec(json.dumps(_spec()))), actor=admin, request=_Req())
    bia = db.scalar(select(User).where(User.email == "bia.import@exemplo.com"))
    bia.is_active = False
    bia.is_superuser = True
    db.commit()

    # novo arquivo com MENOS permissões e is_superuser false
    spec = _spec(users=[{"email": "bia.import@exemplo.com", "client_code": "IMPX1",
                         "is_superuser": False, "permissions": []}])
    plan = oi.build_plan(db, oi.parse_spec(json.dumps(spec)))
    assert any("INATIVO" in w for w in plan.warnings)
    oi.apply_plan(db, plan, actor=admin, request=_Req())
    db.expire_all()
    bia = db.scalar(select(User).where(User.email == "bia.import@exemplo.com"))
    assert bia.is_active is False and bia.is_superuser is True
    assert _grants(db, "bia.import@exemplo.com") == ["protocolo.ler"]


def test_username_collision_is_disambiguated_within_same_file(db):
    spec = {
        "app_slug": APP,
        "users": [
            {"email": "joao@a.com", "username": "joao.imp"},
            {"email": "joao@b.com", "username": "joao.imp"},
        ],
    }
    plan = oi.build_plan(db, oi.parse_spec(json.dumps(spec)))
    names = [u.username for u in plan.user_items]
    assert len(set(names)) == 2 and names[0] == "joao.imp"


def test_superuser_promotion_is_flagged(db):
    spec = {"app_slug": APP, "users": [{"email": "chefe.imp@x.com", "is_superuser": True}]}
    plan = oi.build_plan(db, oi.parse_spec(json.dumps(spec)))
    assert plan.superuser_promotions and any("ADMINISTRADOR" in w for w in plan.warnings)


@pytest.mark.parametrize(
    "spec, fragment",
    [
        ({"app_slug": "nao-existe-slug", "users": []}, "não está cadastrado"),
        ({"app_slug": APP, "users": [{"email": "x@y.com", "client_code": "SEMCLI"}]}, "SEMCLI"),
        ({"app_slug": APP, "users": [{"email": "invalido"}]}, "e-mail inválido"),
        ({"app_slug": APP, "users": [{"email": "d@d.com"}, {"email": "D@d.com"}]}, "mais de uma vez"),
    ],
)
def test_invalid_specs_stop_before_writing(db, spec, fragment):
    with pytest.raises(oi.SpecError) as exc:
        oi.build_plan(db, oi.parse_spec(json.dumps(spec)))
    assert fragment in str(exc.value)


def test_routes_preview_confirm_and_admin_only(admin_client):
    from fastapi.testclient import TestClient

    from app.main import app

    payload = json.dumps({"app_slug": APP, "users": [{"email": "rota.imp@x.com", "full_name": "Rota"}]})
    # sem login (cliente novo, sem cookie) -> redireciona pro login
    anon = TestClient(app)
    assert anon.get("/operadores/importar", follow_redirects=False).status_code == 302
    assert anon.post("/operadores/importar/preview", data={"spec_json": payload},
                     follow_redirects=False).status_code == 302

    assert admin_client.get("/operadores/importar").status_code == 200
    r = admin_client.post("/operadores/importar/preview", data={"spec_json": payload})
    assert r.status_code == 200 and "rota.imp@x.com" in r.text and "Confirmar importação" in r.text
    r = admin_client.post("/operadores/importar/confirmar", data={"spec_json": payload})
    # agora mostra direto a página de resultado, com o link de senha do usuário novo
    assert r.status_code == 200 and "rota.imp@x.com" in r.text and "/definir-senha/" in r.text
    assert "rota.imp@x.com" in admin_client.get("/operadores").text
    bad = admin_client.post("/operadores/importar/preview", data={"spec_json": "{"})
    assert "JSON inválido" in bad.text
