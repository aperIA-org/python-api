"""Testes das rotas de conexão GitHub (`/github`) + helper de `state`."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.git import github_auth
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    github_account_model,
    refresh_token_model,
    remediation_model,
    repository_model,
    scan_job_model,
    scan_report_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.security.github_state import (
    create_connect_state,
    decode_connect_state,
)
from app.infrastructure.security.jwt_handler import create_access_token
from app.main import app


# ------------------------------------------------------------- state helper


def test_state_roundtrip():
    uid = uuid4()
    state = create_connect_state(uid, "segredo")
    assert decode_connect_state(state, "segredo") == uid


def test_state_wrong_secret_raises():
    state = create_connect_state(uuid4(), "segredo")
    with pytest.raises(ValueError):
        decode_connect_state(state, "outro")


def test_state_garbage_raises():
    with pytest.raises(ValueError):
        decode_connect_state("nao-e-jwt", "segredo")


# ------------------------------------------------------------- fixtures HTTP


@pytest.fixture
def session_factory():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    yield factory
    eng.dispose()


@pytest.fixture
def client(session_factory):
    def _override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def user_id():
    return uuid4()


@pytest.fixture
def auth_headers(user_id):
    return {"Authorization": f"Bearer {create_access_token(user_id, settings.SECRET_KEY, 15)}"}


# --------------------------------------------------------------- /connect


def test_connect_requires_auth(client):
    assert client.get("/github/connect").status_code == 401


def test_connect_503_when_app_not_configured(client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_APP_SLUG", "")
    assert client.get("/github/connect", headers=auth_headers).status_code == 503


def test_connect_returns_install_url(client, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_APP_SLUG", "aperia-app")
    resp = client.get("/github/connect", headers=auth_headers)
    assert resp.status_code == 200
    url = resp.json()["install_url"]
    assert "github.com/apps/aperia-app/installations/new" in url
    assert "state=" in url


# --------------------------------------------------------------- /callback


def test_callback_invalid_state(client, monkeypatch):
    # Sem URL de redirect configurada → 400 JSON (contrato antigo preservado).
    monkeypatch.setattr(settings, "GITHUB_CONNECT_REDIRECT_URL", "")
    resp = client.get("/github/callback", params={"installation_id": 1, "state": "xxx"})
    assert resp.status_code == 400


def test_callback_invalid_state_redirects_with_error(client, monkeypatch):
    """State inválido + URL configurada → 302 para o front com github=erro."""
    monkeypatch.setattr(
        settings,
        "GITHUB_CONNECT_REDIRECT_URL",
        "http://localhost:3000/dash/repositorios?github=conectado",
    )
    resp = client.get(
        "/github/callback",
        params={"installation_id": 1, "state": "xxx"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("http://localhost:3000/dash/repositorios?")
    query = dict(parse_qsl(urlsplit(location).query))
    # github=conectado é substituído, não duplicado.
    assert query == {"github": "erro", "motivo": "state"}


def test_callback_invalid_state_redirect_preserves_other_params(client, monkeypatch):
    monkeypatch.setattr(
        settings, "GITHUB_CONNECT_REDIRECT_URL", "http://front/callback?tab=repos"
    )
    resp = client.get(
        "/github/callback",
        params={"installation_id": 1, "state": "expirado"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    query = dict(parse_qsl(urlsplit(resp.headers["location"]).query))
    assert query == {"tab": "repos", "github": "erro", "motivo": "state"}


def test_callback_links_account(client, user_id, auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CONNECT_REDIRECT_URL", "")
    monkeypatch.setattr(
        github_auth, "get_installation_metadata",
        lambda installation_id: {"login": "acme", "type": "Organization"},
    )
    state = create_connect_state(user_id, settings.SECRET_KEY)
    resp = client.get("/github/callback", params={"installation_id": 555, "state": state})
    assert resp.status_code == 200
    assert resp.json()["installation_id"] == 555

    # a conta aparece para o próprio usuário
    accounts = client.get("/github/accounts", headers=auth_headers).json()
    assert len(accounts) == 1
    assert accounts[0]["installation_id"] == 555
    assert accounts[0]["github_login"] == "acme"


def test_callback_redirects_when_configured(client, user_id, monkeypatch):
    monkeypatch.setattr(settings, "GITHUB_CONNECT_REDIRECT_URL", "https://front/ok")
    monkeypatch.setattr(github_auth, "get_installation_metadata", lambda installation_id: {})
    state = create_connect_state(user_id, settings.SECRET_KEY)
    resp = client.get(
        "/github/callback", params={"installation_id": 7, "state": state},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://front/ok"


# --------------------------------------------------------------- /accounts


def test_accounts_requires_auth(client):
    assert client.get("/github/accounts").status_code == 401


def test_delete_account_isolation(client, user_id, auth_headers, monkeypatch):
    # usuário A conecta uma conta
    monkeypatch.setattr(github_auth, "get_installation_metadata", lambda installation_id: {"login": "a", "type": "User"})
    state = create_connect_state(user_id, settings.SECRET_KEY)
    client.get("/github/callback", params={"installation_id": 111, "state": state})
    account_id = client.get("/github/accounts", headers=auth_headers).json()[0]["id"]

    # usuário B (outro token) não consegue deletar → 404
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    assert client.delete(f"/github/accounts/{account_id}", headers=other).status_code == 404

    # dono deleta → 204
    assert client.delete(f"/github/accounts/{account_id}", headers=auth_headers).status_code == 204
    assert client.get("/github/accounts", headers=auth_headers).json() == []
