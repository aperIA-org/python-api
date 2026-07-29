"""Testes das rotas de repositórios (`/repositories`) + `GET /github/repos`.

Cobrem CRUD, isolamento entre usuários e a listagem ao vivo (GitHubClient
mockado no namespace do módulo de rotas).
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.domain.github.entities import GithubAccount, Repository
from app.domain.scan.entities import ScanJob
from app.domain.scan.report_entities import ScanReport
from app.infrastructure.database.sqlalchemy import get_db
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
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_github_account_repository import (
    SQLAlchemyGithubAccountRepository,
)
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)
from app.infrastructure.security.jwt_handler import create_access_token
from app.main import app


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


@pytest.fixture
def account(session_factory, user_id):
    """Cria uma GithubAccount para o usuário e devolve seu id."""
    acc = GithubAccount(user_id=user_id, installation_id=42, github_login="acme", account_type="User")
    with session_factory() as s:
        SQLAlchemyGithubAccountRepository(s).save(acc)
        s.commit()
        return SQLAlchemyGithubAccountRepository(s).get_by_installation(42).id


def _create_payload(account_id, **overrides):
    base = {
        "github_account_id": str(account_id),
        "github_repo_id": 100,
        "full_name": "acme/api",
        "url": "https://github.com/acme/api",
        "default_branch": "main",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------- CRUD


def test_list_requires_auth(client):
    assert client.get("/repositories").status_code == 401


def test_activate_and_list(client, auth_headers, account):
    resp = client.post("/repositories", headers=auth_headers, json=_create_payload(account))
    assert resp.status_code == 201
    assert resp.json()["full_name"] == "acme/api"
    assert resp.json()["active"] is True

    lst = client.get("/repositories", headers=auth_headers).json()
    assert len(lst) == 1


def test_activate_rejects_foreign_account(client, account):
    # usuário B tenta ativar usando a conta de A → 404
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    resp = client.post("/repositories", headers=other, json=_create_payload(account))
    assert resp.status_code == 404


def test_toggle_and_delete(client, auth_headers, account):
    rid = client.post("/repositories", headers=auth_headers, json=_create_payload(account)).json()["id"]

    r = client.patch(f"/repositories/{rid}", headers=auth_headers, json={"active": False})
    assert r.status_code == 200 and r.json()["active"] is False

    assert client.delete(f"/repositories/{rid}", headers=auth_headers).status_code == 204
    assert client.get(f"/repositories/{rid}", headers=auth_headers).status_code == 404


def test_detail_isolation(client, auth_headers, account):
    rid = client.post("/repositories", headers=auth_headers, json=_create_payload(account)).json()["id"]
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    # usuário B não vê o repo de A
    assert client.get(f"/repositories/{rid}", headers=other).status_code == 404
    assert client.get("/repositories", headers=other).json() == []


# --------------------------------------------------- GET /github/repos (live)


def test_available_repos_marks_active(client, auth_headers, account):
    # ativa um repo (id 100) para o usuário
    client.post("/repositories", headers=auth_headers, json=_create_payload(account, github_repo_id=100))

    fake = [
        {"id": 100, "full_name": "acme/api", "html_url": "u1", "default_branch": "main"},
        {"id": 200, "full_name": "acme/web", "html_url": "u2", "default_branch": "dev"},
    ]
    with patch("app.presentation.api.routes.github_routes.GitHubClient") as MockClient:
        MockClient.return_value.list_repositories.return_value = fake
        resp = client.get("/github/repos", headers=auth_headers)

    assert resp.status_code == 200
    by_id = {r["github_repo_id"]: r for r in resp.json()}
    assert by_id[100]["active"] is True
    assert by_id[200]["active"] is False


def test_available_repos_empty_without_accounts(client, auth_headers):
    # usuário sem conta conectada → lista vazia (não chama GitHub)
    assert client.get("/github/repos", headers=auth_headers).json() == []


# --------------------------------------------- rotas por repositório + isolamento


@pytest.fixture
def repo_with_data(session_factory, user_id, account):
    """Cria um Repository do usuário + ScanJob/Finding/ScanReport de um commit."""
    sha = "d" * 40
    rid = uuid4()
    with session_factory() as s:
        SQLAlchemyRepositoryRepository(s).save(
            Repository(id=rid, user_id=user_id, github_account_id=account,
                       installation_id=42, github_repo_id=100, full_name="acme/api",
                       url="https://github.com/acme/api")
        )
        SQLAlchemyScanJobRepository(s).save(
            ScanJob(commit_sha=sha, repo_url="https://github.com/acme/api",
                    installation_id=42, user_id=user_id, repository_id=rid)
        )
        SQLAlchemyFindingRepository(s).bulk_save([
            Finding(source="semgrep", severity=Severity.HIGH, title="t", description="d",
                    commit_sha=sha, repo_url="https://github.com/acme/api", tier=2)
        ])
        SQLAlchemyScanReportRepository(s).save(
            ScanReport(commit_sha=sha, tier=2, report_markdown="## r",
                       analysis_json={}, degraded=False, comment_id=1, posted=True)
        )
        s.commit()
    return rid


def test_repository_scans_findings_reports(client, auth_headers, repo_with_data):
    rid = repo_with_data
    scans = client.get(f"/repositories/{rid}/scans", headers=auth_headers).json()
    assert scans["total"] == 1
    findings = client.get(f"/repositories/{rid}/findings", headers=auth_headers).json()
    assert findings["total"] == 1
    reports = client.get(f"/repositories/{rid}/reports", headers=auth_headers).json()
    assert len(reports) == 1 and reports[0]["tier"] == 2


def test_repository_subroutes_isolation(client, repo_with_data):
    rid = repo_with_data
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    assert client.get(f"/repositories/{rid}/scans", headers=other).status_code == 404
    assert client.get(f"/repositories/{rid}/findings", headers=other).status_code == 404
    assert client.get(f"/repositories/{rid}/reports", headers=other).status_code == 404
