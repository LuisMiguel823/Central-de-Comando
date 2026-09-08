from __future__ import annotations

import pytest

from app.config import settings
from app.services import loginunico

LOCATION = "https://loginunico.cabofrio.rj.gov.br/loginunico/form.jsp?sys=SLU&formID=%7BABC%7D&token=TK123"


def _fake_http_get_factory(user_payload: dict):
    def _fake(url: str, params: dict) -> dict:
        if "WSAuthInit" in url:
            assert params["redirect"] == settings.loginunico_callback_url
            return {"expires_in": "2025-01-01 00:00:00", "location": LOCATION, "token": "TK123"}
        if "WSAuthVerify" in url:
            assert params["token"] == "TK123"
            return user_payload
        raise AssertionError(f"URL inesperada: {url}")

    return _fake


@pytest.fixture
def lu_enabled(monkeypatch):
    monkeypatch.setattr(settings, "loginunico_enabled", True)
    monkeypatch.setattr(settings, "loginunico_provision_active", True)
    monkeypatch.setattr(settings, "loginunico_min_level", 1)
    yield


def test_loginunico_full_flow(client, lu_enabled, monkeypatch):
    payload = {
        "nome": "Maria Teste da Silva",
        "email": "maria.teste@cabofrio.rj.gov.br",
        "cpf": "123.456.789-09",
        "nivel": "2",
        "foto": "https://loginunico.cabofrio.rj.gov.br/foto/maria.jpg",
    }
    monkeypatch.setattr(loginunico, "_http_get", _fake_http_get_factory(payload))

    # passo 1 + 2
    r = client.get("/auth/loginunico/login", params={"next": "/"}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == LOCATION

    # passo 3
    r = client.get("/auth/loginunico/callback", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/"

    # sessão logada
    assert client.get("/").status_code == 200
    ops = client.get("/operadores")
    assert "Maria Teste da Silva" in ops.text
    assert "12345678909" in ops.text  # CPF normalizado
    assert "Login Único N2" in ops.text


def test_loginunico_level_below_minimum(client, lu_enabled, monkeypatch):
    monkeypatch.setattr(settings, "loginunico_min_level", 3)
    payload = {"nome": "João Nível Baixo", "cpf": "111.222.333-44", "nivel": "1"}
    monkeypatch.setattr(loginunico, "_http_get", _fake_http_get_factory(payload))

    client.get("/auth/loginunico/login", follow_redirects=False)
    r = client.get("/auth/loginunico/callback", follow_redirects=False)
    assert r.status_code == 302
    assert "insuficiente" in r.headers["location"].lower()


def test_loginunico_disabled_redirects(client):
    r = client.get("/auth/loginunico/login", follow_redirects=False)
    assert r.status_code == 302
    assert "n%C3%A3o+configurado" in r.headers["location"]


def test_normalize_user_key_variants():
    out = loginunico.normalize_user(
        {"NOME": "Fulana", "E-MAIL": "F@x.com", "CPF": "529.982.247-25", "NIVEL": "3"}
    )
    assert out["ok"] is True
    assert out["name"] == "Fulana"
    assert out["email"] == "f@x.com"
    assert out["cpf"] == "52998224725"
    assert out["account_level"] == 3
