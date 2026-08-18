"""E2E multi-tenant: webhook → atribuição de dono → leitura isolada.

Fecha a lacuna prometida: prova que um PR num repositório CADASTRADO gera um
ScanJob atribuído ao dono, que o dono consegue ler via `/repositories/{id}/scans`
e que OUTRO usuário recebe 404. O canvas Celery completo é coberto em
`test_full_pipeline.py`; aqui o `start_pipeline` é substituído por um stub que
apenas persiste o ScanJob (o elo que nos interessa).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.core import orchestrator
from app.domain.github.entities import Repository
from app.infrastructure.database import sqlalchemy as db_module
from app.infrastructure.persistence import scan_job_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    github_account_model,
    refresh_token_model,
    remediation_model,
    repository_model,
    scan_job_model,
    scan_report_model,
    scan_tool_run_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)
from app.infrastructure.security.jwt_handler import create_access_token
from app.main import app
from app.presentation.api.routes import webhook_routes

WEBHOOK_SECRET = "e2e-secret"


def _sign(payload: bytes) -> str:
    return "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()


@pytest.fixture
def sqlite_factory():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False},
                        poolclass=StaticPool, future=True)
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    yield factory
    eng.dispose()


@pytest.fixture
def client(sqlite_factory, monkeypatch):
    # Persistência ligada + todos os SessionLocal apontando pro mesmo sqlite.
    monkeypatch.setattr(settings, "SCAN_PERSISTENCE_ENABLED", True)
    monkeypatch.setattr(webhook_routes.settings, "GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setattr(db_module, "SessionLocal", sqlite_factory)
    monkeypatch.setattr(scan_job_writer, "SessionLocal", sqlite_factory)

    def _override_get_db():
        s = sqlite_factory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db := db_module.get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def test_webhook_attributes_scan_and_isolates_read(client, sqlite_factory, monkeypatch):
    user_id = uuid4()
    repo_id = uuid4()
    # repositório cadastrado + ativo do usuário
    with sqlite_factory() as s:
        SQLAlchemyRepositoryRepository(s).save(
            Repository(id=repo_id, user_id=user_id, github_account_id=uuid4(),
                       installation_id=999, github_repo_id=555, full_name="acme/api",
                       url="https://github.com/acme/api", active=True)
        )
        s.commit()

    # start_pipeline vira um stub que só persiste o ScanJob (com o dono resolvido).
    def fake_start_pipeline(**kwargs):
        scan_job_writer.create_scan_job(
            commit_sha=kwargs["commit_sha"], repo_url=kwargs["repo_url"],
            installation_id=kwargs["installation_id"], pr_number=kwargs.get("pr_number"),
            repo_full_name=kwargs.get("repo_full_name"),
            user_id=kwargs.get("user_id"), repository_id=kwargs.get("repository_id"),
        )
    monkeypatch.setattr(orchestrator, "start_pipeline", fake_start_pipeline)

    payload_obj = {
        "action": "opened",
        "installation": {"id": 999},
        "pull_request": {"number": 3, "head": {"sha": "e" * 40}, "base": {"sha": "f" * 40}},
        "repository": {"id": 555, "clone_url": "https://github.com/acme/api.git", "full_name": "acme/api"},
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post("/webhook/github", content=payload, headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(payload),
        "X-GitHub-Event": "pull_request",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"

    # o dono enxerga o scan pelo repositório
    headers = {"Authorization": f"Bearer {create_access_token(user_id, settings.SECRET_KEY, 15)}"}
    scans = client.get(f"/repositories/{repo_id}/scans", headers=headers).json()
    assert scans["total"] == 1

    # outro usuário → 404 (isolamento)
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    assert client.get(f"/repositories/{repo_id}/scans", headers=other).status_code == 404


def test_webhook_unregistered_repo_is_orphan(client, sqlite_factory, monkeypatch):
    """PR de repo NÃO cadastrado ainda roda, mas o scan fica sem dono."""
    captured = {}

    def fake_start_pipeline(**kwargs):
        captured.update(kwargs)
    monkeypatch.setattr(orchestrator, "start_pipeline", fake_start_pipeline)

    payload_obj = {
        "action": "opened",
        "installation": {"id": 888},
        "pull_request": {"number": 1, "head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}},
        "repository": {"id": 777, "clone_url": "https://github.com/x/y.git", "full_name": "x/y"},
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post("/webhook/github", content=payload, headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(payload),
        "X-GitHub-Event": "pull_request",
    })
    assert resp.status_code == 200
    assert captured["user_id"] is None
    assert captured["repository_id"] is None


def test_webhook_repassa_target_url_do_repositorio(client, sqlite_factory, monkeypatch):
    """Gatilho por webhook: o alvo do DAST vem do repositório cadastrado.

    O payload do GitHub não diz onde a aplicação está publicada — quem sabe é
    o repositório, resolvido pela instalação. Sem isso o Tier 3 continuaria
    pulando o ZAP mesmo com a URL cadastrada.
    """
    user_id = uuid4()
    with sqlite_factory() as s:
        SQLAlchemyRepositoryRepository(s).save(
            Repository(user_id=user_id, github_account_id=uuid4(),
                       installation_id=777, github_repo_id=888, full_name="acme/web",
                       url="https://github.com/acme/web", active=True,
                       target_url="https://staging.acme.com")
        )
        s.commit()

    capturado = {}
    monkeypatch.setattr(orchestrator, "start_pipeline", lambda **kw: capturado.update(kw))

    payload_obj = {
        "action": "opened",
        "installation": {"id": 777},
        "pull_request": {"number": 9, "head": {"sha": "1" * 40}, "base": {"sha": "2" * 40}},
        "repository": {"id": 888, "clone_url": "https://github.com/acme/web.git",
                       "full_name": "acme/web"},
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post("/webhook/github", content=payload, headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(payload),
        "X-GitHub-Event": "pull_request",
    })

    assert resp.status_code == 200
    assert capturado["target_url"] == "https://staging.acme.com"
    assert capturado["user_id"] == user_id


def test_webhook_sem_repositorio_cadastrado_nao_tem_alvo(client, monkeypatch):
    """PR de repositório desconhecido: sem dono e sem alvo — ZAP segue pulado."""
    capturado = {}
    monkeypatch.setattr(orchestrator, "start_pipeline", lambda **kw: capturado.update(kw))

    payload_obj = {
        "action": "opened",
        "installation": {"id": 4242},
        "pull_request": {"number": 1, "head": {"sha": "3" * 40}, "base": {"sha": "4" * 40}},
        "repository": {"id": 4343, "clone_url": "https://github.com/x/y.git", "full_name": "x/y"},
    }
    payload = json.dumps(payload_obj).encode()
    resp = client.post("/webhook/github", content=payload, headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": _sign(payload),
        "X-GitHub-Event": "pull_request",
    })

    assert resp.status_code == 200
    assert capturado["target_url"] is None
    assert capturado["user_id"] is None
