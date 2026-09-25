from __future__ import annotations

from sqlalchemy import select

from app.core.security import hash_password
from app.database import SessionLocal
from app.models import Application, Client, ClientTier, User, UserAppClient
from app.services import oidc


def _mk(db):
    app1 = db.scalar(select(Application).where(Application.slug == "app-1"))
    cli = db.scalar(select(Client).where(Client.code == "UACX1"))
    if cli is None:
        cli = Client(code="UACX1", name="Cliente UAC", tier=ClientTier.BRONZE)
        db.add(cli)
    u = db.scalar(select(User).where(User.username == "uac.user"))
    if u is None:
        u = User(username="uac.user", email="uac.user@x.com", full_name="Uac User",
                 password_hash=hash_password("x12345678"))
        db.add(u)
    db.commit()
    return app1, cli, u


def test_claim_uses_per_app_client_then_falls_back_to_general(admin_client):
    db = SessionLocal()
    try:
        app1, cli, u = _mk(db)
        # sem nada: sem client_code
        assert "client_code" not in oidc.userinfo_claims(db, u, app1, "openid")

        # cadastro geral vira só o padrão
        other = Client(code="UACG1", name="Geral", tier=ClientTier.BRONZE)
        db.add(other)
        db.commit()
        u.client_id = other.id
        db.commit()
        assert oidc.userinfo_claims(db, u, app1, "openid")["client_code"] == "UACG1"

        # vínculo do sistema tem prioridade
        db.add(UserAppClient(user_id=u.id, application_id=app1.id, client_id=cli.id))
        db.commit()
        assert oidc.userinfo_claims(db, u, app1, "openid")["client_code"] == "UACX1"
    finally:
        db.close()


def test_module_page_saves_and_clears_client_per_system(admin_client):
    db = SessionLocal()
    try:
        app1, cli, u = _mk(db)
        app_id, uid, cid = app1.id, u.id, cli.id
        db.query(UserAppClient).filter_by(user_id=uid, application_id=app_id).delete()
        db.commit()
    finally:
        db.close()

    page = admin_client.get("/apps/app-1")
    assert page.status_code == 200 and f'name="client_{uid}"' in page.text

    r = admin_client.post(f"/apps/{app_id}/usuarios", data={f"client_{uid}": str(cid)}, follow_redirects=False)
    assert r.status_code == 302
    db = SessionLocal()
    try:
        link = db.scalar(select(UserAppClient).where(
            UserAppClient.user_id == uid, UserAppClient.application_id == app_id))
        assert link is not None and link.client_id == cid
    finally:
        db.close()

    # vazio remove o vínculo
    admin_client.post(f"/apps/{app_id}/usuarios", data={f"client_{uid}": ""})
    db = SessionLocal()
    try:
        assert db.scalar(select(UserAppClient).where(
            UserAppClient.user_id == uid, UserAppClient.application_id == app_id)) is None
    finally:
        db.close()
