"""Testes das rotas de repositórios (`/repositories`) + `GET /github/repos`.

Cobrem CRUD, isolamento entre usuários e a listagem ao vivo (GitHubClient
mockado no namespace do módulo de rotas).
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID, uuid4

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
from app.domain.scan.value_objects import TierStatus
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


# ------------------------------------------- upsert devolve o id persistido


def test_activate_twice_returns_the_persisted_id(client, auth_headers, account):
    """POST repetido é upsert: a resposta traz o id da linha que existe.

    Antes o id vinha da entidade em memória (uuid4 novo a cada POST), e um
    PATCH/DELETE com ele dava 404.
    """
    first = client.post("/repositories", headers=auth_headers, json=_create_payload(account))
    second = client.post("/repositories", headers=auth_headers, json=_create_payload(account))
    assert first.status_code == second.status_code == 201
    assert second.json()["id"] == first.json()["id"]

    # o id devolvido existe de fato no banco
    rid = second.json()["id"]
    assert client.get(f"/repositories/{rid}", headers=auth_headers).status_code == 200
    assert client.patch(
        f"/repositories/{rid}", headers=auth_headers, json={"active": False}
    ).status_code == 200


def test_reactivate_via_post_keeps_id_and_sets_active(client, auth_headers, account):
    rid = client.post("/repositories", headers=auth_headers, json=_create_payload(account)).json()["id"]
    client.patch(f"/repositories/{rid}", headers=auth_headers, json={"active": False})

    again = client.post("/repositories", headers=auth_headers, json=_create_payload(account))
    assert again.status_code == 201
    assert again.json()["id"] == rid
    assert again.json()["active"] is True
    assert len(client.get("/repositories", headers=auth_headers).json()) == 1


def test_repository_save_returns_persisted_row(session_factory, user_id, account):
    """O repositório de infra devolve a linha efetivamente persistida."""
    with session_factory() as s:
        store = SQLAlchemyRepositoryRepository(s)
        first = store.save(
            Repository(user_id=user_id, github_account_id=account, installation_id=42,
                       github_repo_id=100, full_name="acme/api", url="u")
        )
        s.commit()
        second = store.save(
            Repository(user_id=user_id, github_account_id=account, installation_id=42,
                       github_repo_id=100, full_name="acme/api-renomeado", url="u")
        )
        s.commit()

    assert second.id == first.id
    assert second.full_name == "acme/api-renomeado"


# ------------------------------------ metadados extras em GET /github/repos


def test_available_repos_exposes_metadata(client, auth_headers, account):
    fake = [
        {
            "id": 100, "full_name": "acme/api", "html_url": "u1", "default_branch": "main",
            "private": True, "language": "Python", "pushed_at": "2024-06-29T16:00:00Z",
        },
        # payload mínimo (sem os metadados) → defaults, sem quebrar
        {"id": 200, "full_name": "acme/web", "html_url": "u2", "default_branch": "dev"},
    ]
    with patch("app.presentation.api.routes.github_routes.GitHubClient") as MockClient:
        MockClient.return_value.list_repositories.return_value = fake
        resp = client.get("/github/repos", headers=auth_headers)

    by_id = {r["github_repo_id"]: r for r in resp.json()}
    assert by_id[100]["private"] is True
    assert by_id[100]["language"] == "Python"
    assert by_id[100]["pushed_at"].startswith("2024-06-29T16:00:00")
    assert by_id[200]["private"] is False
    assert by_id[200]["language"] is None
    assert by_id[200]["pushed_at"] is None


# ------------------------ desconectar conta remove repos, preserva histórico


def test_delete_account_removes_repositories_keeping_history(
    client, auth_headers, session_factory, repo_with_data, account
):
    assert len(client.get("/repositories", headers=auth_headers).json()) == 1

    assert client.delete(f"/github/accounts/{account}", headers=auth_headers).status_code == 204

    # repositórios da conta somem (não viram fantasmas)
    assert client.get("/repositories", headers=auth_headers).json() == []
    with session_factory() as s:
        assert SQLAlchemyRepositoryRepository(s).get_by_id(repo_with_data) is None
        # ...mas o histórico já coletado permanece
        assert SQLAlchemyScanJobRepository(s).count_by_repository(repo_with_data) == 1
        assert SQLAlchemyFindingRepository(s).count(repository_id=repo_with_data) == 1
        assert len(SQLAlchemyScanReportRepository(s).list_by_repository(repo_with_data)) == 1


def test_delete_account_does_not_touch_other_accounts_repos(
    client, auth_headers, session_factory, user_id, account
):
    outra_conta = uuid4()
    with session_factory() as s:
        SQLAlchemyRepositoryRepository(s).save(
            Repository(user_id=user_id, github_account_id=outra_conta, installation_id=77,
                       github_repo_id=999, full_name="acme/outro", url="u")
        )
        s.commit()
    client.post("/repositories", headers=auth_headers, json=_create_payload(account))

    client.delete(f"/github/accounts/{account}", headers=auth_headers)

    restantes = client.get("/repositories", headers=auth_headers).json()
    assert [r["full_name"] for r in restantes] == ["acme/outro"]


# ------------------------------------------------- POST /repositories/{id}/scan


@pytest.fixture
def github_app_configured(monkeypatch):
    """Credenciais do App presentes — sem elas a rota responde 503."""
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "1234")
    monkeypatch.setattr(settings, "GITHUB_PRIVATE_KEY_PATH", "/tmp/aperia.pem")


@pytest.fixture
def pipeline_spy(monkeypatch):
    """Substitui o start_pipeline real (mesmo alvo usado nos testes de webhook)."""
    from unittest.mock import MagicMock

    from app.core import orchestrator

    spy = MagicMock()
    monkeypatch.setattr(orchestrator, "start_pipeline", spy)
    return spy


def _repo_id(client, auth_headers, account, **overrides):
    return client.post(
        "/repositories", headers=auth_headers, json=_create_payload(account, **overrides)
    ).json()["id"]


def test_manual_scan_dispatches_same_pipeline(
    client, auth_headers, account, user_id, github_app_configured, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)

    with patch("app.presentation.api.routes.repository_routes.GitHubClient") as MockClient:
        MockClient.return_value.get_branch_head_sha.return_value = "c" * 40
        resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 202
    assert resp.json() == {"status": "queued", "commit_sha": "c" * 40, "branch": "main"}
    MockClient.assert_called_once_with(42)
    MockClient.return_value.get_branch_head_sha.assert_called_once_with("acme/api", "main")

    kwargs = pipeline_spy.call_args.kwargs
    assert kwargs["pr_number"] is None  # scan de branch, não de PR
    assert kwargs["commit_sha"] == "c" * 40
    assert kwargs["head_sha"] == "c" * 40
    assert kwargs["base_sha"] == "c" * 40
    assert kwargs["installation_id"] == 42
    assert kwargs["repo_full_name"] == "acme/api"
    assert kwargs["user_id"] == user_id
    assert str(kwargs["repository_id"]) == rid


def test_manual_scan_404_for_other_user(client, auth_headers, account, github_app_configured):
    rid = _repo_id(client, auth_headers, account)
    other = {"Authorization": f"Bearer {create_access_token(uuid4(), settings.SECRET_KEY, 15)}"}
    assert client.post(f"/repositories/{rid}/scan", headers=other).status_code == 404


def test_manual_scan_404_for_unknown_repository(client, auth_headers, github_app_configured):
    assert client.post(f"/repositories/{uuid4()}/scan", headers=auth_headers).status_code == 404


def test_manual_scan_409_when_inactive(
    client, auth_headers, account, github_app_configured, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)
    client.patch(f"/repositories/{rid}", headers=auth_headers, json={"active": False})

    resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 409
    assert "desativado" in resp.json()["detail"].lower()
    pipeline_spy.assert_not_called()


def test_manual_scan_409_when_scan_in_progress(
    client, auth_headers, account, session_factory, user_id, github_app_configured, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(
            ScanJob(commit_sha="c" * 40, repo_url="https://github.com/acme/api",
                    installation_id=42, user_id=user_id, repository_id=UUID(rid),
                    tier1_status=TierStatus.RUNNING)
        )
        s.commit()

    with patch("app.presentation.api.routes.repository_routes.GitHubClient") as MockClient:
        MockClient.return_value.get_branch_head_sha.return_value = "c" * 40
        resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 409
    assert "andamento" in resp.json()["detail"]
    pipeline_spy.assert_not_called()


def test_manual_scan_allows_new_scan_when_previous_finished(
    client, auth_headers, account, session_factory, user_id, github_app_configured, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(
            ScanJob(commit_sha="c" * 40, repo_url="https://github.com/acme/api",
                    installation_id=42, user_id=user_id, repository_id=UUID(rid),
                    tier1_status=TierStatus.DONE, tier2_status=TierStatus.DONE,
                    tier3_status=TierStatus.SKIPPED)
        )
        s.commit()

    with patch("app.presentation.api.routes.repository_routes.GitHubClient") as MockClient:
        MockClient.return_value.get_branch_head_sha.return_value = "c" * 40
        resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 202
    pipeline_spy.assert_called_once()


def test_manual_scan_503_without_github_app(
    client, auth_headers, account, monkeypatch, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)
    monkeypatch.setattr(settings, "GITHUB_APP_ID", "")

    resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 503
    pipeline_spy.assert_not_called()


def test_manual_scan_502_when_github_fails(
    client, auth_headers, account, github_app_configured, pipeline_spy
):
    rid = _repo_id(client, auth_headers, account)

    with patch("app.presentation.api.routes.repository_routes.GitHubClient") as MockClient:
        MockClient.return_value.get_branch_head_sha.side_effect = RuntimeError("boom")
        resp = client.post(f"/repositories/{rid}/scan", headers=auth_headers)

    assert resp.status_code == 502
    pipeline_spy.assert_not_called()


def test_manual_scan_requires_auth(client, auth_headers, account, github_app_configured):
    rid = _repo_id(client, auth_headers, account)
    assert client.post(f"/repositories/{rid}/scan").status_code == 401
