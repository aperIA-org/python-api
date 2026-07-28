"""Testes das rotas de status de scan (`/scans`).

Caminho HTTP real (TestClient) com JWT válido e Session sqlite injetada
via override de ``get_db``.
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
from app.domain.finding.value_objects import Severity
from app.domain.scan.entities import ScanJob
from app.domain.scan.report_entities import ScanReport
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
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


@pytest.fixture
def seeded(session_factory):
    job = ScanJob(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        installation_id=1,
        pr_number=9,
        repo_full_name="acme/repo",
        tier1_status=TierStatus.DONE,
        tier2_status=TierStatus.DONE,
        blocked_at_tier=None,
        final_risk_score=80,
        final_risk_level="high",
    )
    other = ScanJob(
        commit_sha="b" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        tier1_status=TierStatus.RUNNING,
    )
    findings = [
        Finding(source="semgrep", severity=Severity.HIGH, title="t1", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
        Finding(source="trivy", severity=Severity.LOW, title="t2", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
    ]
    report = ScanReport(
        commit_sha="a" * 40, tier=2, report_markdown="## Relatorio Tier 2",
        analysis_json={"risk_score": {"score": 80, "level": "high"}},
        degraded=False, comment_id=123, posted=True,
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(job)
        SQLAlchemyScanJobRepository(s).save(other)
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        SQLAlchemyScanReportRepository(s).save(report)
        s.commit()


def test_list_requires_auth(client):
    assert client.get("/scans").status_code == 401


def test_detail_requires_auth(client):
    assert client.get("/scans/" + "a" * 40).status_code == 401


def test_list_returns_scans(client, auth_headers, seeded):
    resp = client.get("/scans", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    # a listagem enxuta não traz o findings_summary
    assert "findings_summary" not in body["items"][0]


def test_get_by_commit_with_summary(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["commit_sha"] == "a" * 40
    assert body["tier2_status"] == "done"
    assert body["final_risk_score"] == 80
    summary = body["findings_summary"]
    assert summary["total"] == 2
    assert summary["by_severity"] == {"high": 1, "low": 1}
    assert summary["by_tier"] == {"2": 2}


def test_get_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40, headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan nao encontrado"


# --------------------------------------------------------------- relatórios


def test_reports_requires_auth(client):
    assert client.get("/scans/" + "a" * 40 + "/report").status_code == 401


def test_list_reports(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["commit_sha"] == "a" * 40
    assert len(body["reports"]) == 1
    assert body["reports"][0]["tier"] == 2
    assert body["reports"][0]["comment_id"] == 123


def test_list_reports_empty_but_scan_exists(client, auth_headers, seeded):
    # 'b' tem ScanJob mas nenhum relatório → 200 com lista vazia
    resp = client.get("/scans/" + "b" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["reports"] == []


def test_list_reports_scan_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40 + "/report", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan nao encontrado"


def test_report_by_tier(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/2/report", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == 2
    assert body["report_markdown"] == "## Relatorio Tier 2"
    assert body["analysis_json"]["risk_score"]["score"] == 80


def test_report_by_tier_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/3/report", headers=auth_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Relatorio nao encontrado"


def test_report_by_tier_out_of_range(client, auth_headers, seeded):
    resp = client.get("/scans/" + "a" * 40 + "/tiers/9/report", headers=auth_headers)
    assert resp.status_code == 422
