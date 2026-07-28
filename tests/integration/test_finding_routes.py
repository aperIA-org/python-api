"""Testes das rotas de consumo de findings (`/findings`).

Exercita o caminho HTTP real (TestClient) com:
- JWT valido emitido por ``create_access_token`` (auth real, sem override);
- Session sqlite in-memory injetada via override de ``get_db``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.persistence.models import (  # noqa: F401 — registra metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.security.jwt_handler import create_access_token
from app.main import app


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


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
def auth_headers() -> dict[str, str]:
    token = create_access_token(uuid4(), settings.SECRET_KEY, 15)
    return {"Authorization": f"Bearer {token}"}


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "f-string em query",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/db.py",
        "line_number": 42,
        "tier": 1,
    }
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def seeded(session_factory):
    """Persiste 3 findings variados e devolve a lista de entidades."""
    findings = [
        _make_finding(severity=Severity.CRITICAL, source="trufflehog", tier=1,
                      secret_verified=True, secret_type="aws", title="AWS key vazada"),
        _make_finding(severity=Severity.HIGH, source="semgrep", tier=2,
                      cve_id=CVEId("CVE-2024-1234"), raw_output={"rule": "sqli"}),
        _make_finding(severity=Severity.LOW, source="trivy", tier=2,
                      commit_sha="b" * 40, title="Dep desatualizada"),
    ]
    with session_factory() as s:
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        s.commit()
    return findings


# ----------------------------------------------------------------- auth


def test_list_requires_auth(client):
    resp = client.get("/findings")
    assert resp.status_code == 401


def test_detail_requires_auth(client):
    resp = client.get(f"/findings/{uuid4()}")
    assert resp.status_code == 401


def test_rejects_garbage_token(client):
    resp = client.get("/findings", headers={"Authorization": "Bearer nao-e-jwt"})
    assert resp.status_code == 401


# ----------------------------------------------------------------- listagem


def test_list_returns_all(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    # raw_output nao aparece na listagem
    assert "raw_output" not in body["items"][0]


def test_filter_by_severity(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"severity": "critical"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"
    assert body["items"][0]["secret_verified"] is True


def test_filter_by_commit_sha(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"commit_sha": "b" * 40})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["source"] == "trivy"


def test_filter_by_tier(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"tier": 2})
    assert resp.status_code == 200
    assert resp.json()["total"] == 2


def test_pagination_limit(client, auth_headers, seeded):
    resp = client.get("/findings", headers=auth_headers, params={"limit": 1})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3          # total ignora paginacao
    assert len(body["items"]) == 1     # pagina respeita o limit
    assert body["limit"] == 1


def test_invalid_severity_returns_422(client, auth_headers):
    resp = client.get("/findings", headers=auth_headers, params={"severity": "meh"})
    assert resp.status_code == 422


def test_invalid_tier_returns_422(client, auth_headers):
    resp = client.get("/findings", headers=auth_headers, params={"tier": 9})
    assert resp.status_code == 422


# ----------------------------------------------------------------- detalhe


def test_detail_returns_raw_output(client, auth_headers, seeded):
    target = next(f for f in seeded if f.source == "semgrep")
    resp = client.get(f"/findings/{target.id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(target.id)
    assert body["cve_id"] == "CVE-2024-1234"
    assert body["raw_output"] == {"rule": "sqli"}


def test_detail_not_found(client, auth_headers, seeded):
    resp = client.get(f"/findings/{uuid4()}", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Finding nao encontrado"
