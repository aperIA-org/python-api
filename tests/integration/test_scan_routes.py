"""Testes das rotas de status de scan (`/scans`).

Caminho HTTP real (TestClient) com JWT válido e Session sqlite injetada
via override de ``get_db``.
"""

from __future__ import annotations

from datetime import datetime
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
def auth_headers(user_id) -> dict[str, str]:
    token = create_access_token(user_id, settings.SECRET_KEY, 15)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_id():
    return uuid4()


@pytest.fixture
def seeded(session_factory, user_id):
    """Devolve o id da execução corrente de 'a'*40.

    O relatório é gravado ligado a ela: ``scan_job_id`` é NOT NULL desde que um
    relatório passou a pertencer à execução, e não ao commit.
    """
    job = ScanJob(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        installation_id=1,
        pr_number=9,
        repo_full_name="acme/repo",
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 8, 1, 12, 0),
        tier2_status=TierStatus.DONE,
        blocked_at_tier=None,
        final_risk_score=80,
        final_risk_level="high",
        user_id=user_id,
    )
    other = ScanJob(
        commit_sha="b" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        tier1_status=TierStatus.RUNNING, user_id=user_id,
    )
    findings = [
        Finding(source="semgrep", severity=Severity.HIGH, title="t1", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
        Finding(source="trivy", severity=Severity.LOW, title="t2", description="d",
                commit_sha="a" * 40, repo_url="https://github.com/acme/repo", tier=2),
    ]
    report = ScanReport(
        commit_sha="a" * 40, scan_job_id=job.id, tier=2,
        report_markdown="## Relatorio Tier 2",
        analysis_json={"risk_score": {"score": 80, "level": "high"}},
        degraded=False, comment_id=123, posted=True,
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(job)
        SQLAlchemyScanJobRepository(s).save(other)
        SQLAlchemyFindingRepository(s).bulk_save(findings)
        SQLAlchemyScanReportRepository(s).save(report)
        s.commit()
    return job.id


@pytest.fixture
def historico(session_factory, user_id, seeded):
    """Acrescenta uma execução ANTERIOR de 'a'*40, com relatório próprio.

    Devolve ``(corrente, antiga)``. A anterior tem ``tier1_started_at`` explícito
    e mais antigo — é ele, não ``created_at``, que ordena o histórico.
    """
    antiga = ScanJob(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        installation_id=1,
        pr_number=9,
        repo_full_name="acme/repo",
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 7, 20, 8, 0),
        created_at=datetime(2026, 7, 20, 8, 0),
        tier2_status=TierStatus.FAILED,
        final_risk_score=30,
        final_risk_level="low",
        user_id=user_id,
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(antiga)
        SQLAlchemyScanReportRepository(s).save(
            ScanReport(
                commit_sha="a" * 40, scan_job_id=antiga.id, tier=2,
                report_markdown="## Relatorio antigo", analysis_json={},
                degraded=False, comment_id=1, posted=True,
            )
        )
        s.commit()
    return seeded, antiga.id


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


# ------------------------------------------------- histórico de execuções


def test_history_lista_execucoes_da_mais_nova_para_a_mais_antiga(
    client, auth_headers, historico
):
    corrente, antiga = historico
    body = client.get("/scans/" + "a" * 40 + "/history", headers=auth_headers).json()
    assert body["total"] == 2
    assert [i["id"] for i in body["items"]] == [str(corrente), str(antiga)]
    # a execução consultada faz parte da lista
    assert body["items"][1]["final_risk_score"] == 30

    # o histórico é do commit: entrar por qualquer execução dá a mesma lista
    por_uuid = client.get(f"/scans/{antiga}/history", headers=auth_headers).json()
    assert [i["id"] for i in por_uuid["items"]] == [str(corrente), str(antiga)]


def test_history_de_scan_sem_reexecucao_traz_apenas_ele(client, auth_headers, seeded):
    body = client.get("/scans/" + "b" * 40 + "/history", headers=auth_headers).json()
    assert body["total"] == 1
    assert body["items"][0]["commit_sha"] == "b" * 40


def test_history_scan_not_found(client, auth_headers, seeded):
    resp = client.get("/scans/" + "c" * 40 + "/history", headers=auth_headers)
    assert resp.status_code == 404


def test_history_requires_auth(client):
    assert client.get("/scans/" + "a" * 40 + "/history").status_code == 401


def test_uuid_endereca_a_execucao_e_sha_a_corrente(client, auth_headers, historico):
    """As duas formas do path param não são sinônimos quando há histórico.

    O sha responde "como está este commit agora" (execução corrente); o uuid
    endereça uma execução específica — é o que torna o histórico navegável.
    """
    corrente, antiga = historico

    por_sha = client.get("/scans/" + "a" * 40, headers=auth_headers).json()
    assert por_sha["id"] == str(corrente)
    assert por_sha["tier2_status"] == "done"
    assert por_sha["final_risk_score"] == 80

    por_uuid = client.get(f"/scans/{antiga}", headers=auth_headers).json()
    assert por_uuid["id"] == str(antiga)
    assert por_uuid["commit_sha"] == "a" * 40
    assert por_uuid["tier2_status"] == "failed"
    assert por_uuid["final_risk_score"] == 30


def test_relatorios_sao_por_execucao(client, auth_headers, historico):
    """Cada execução guarda o seu markdown — antes o rescan sobrescrevia."""
    corrente, antiga = historico

    atual = client.get("/scans/" + "a" * 40 + "/report", headers=auth_headers).json()
    assert atual["scan_id"] == str(corrente)
    assert [r["report_markdown"] for r in atual["reports"]] == ["## Relatorio Tier 2"]

    velho = client.get(f"/scans/{antiga}/report", headers=auth_headers).json()
    assert velho["scan_id"] == str(antiga)
    assert velho["commit_sha"] == "a" * 40
    assert [r["report_markdown"] for r in velho["reports"]] == ["## Relatorio antigo"]

    por_tier = client.get(f"/scans/{antiga}/tiers/2/report", headers=auth_headers).json()
    assert por_tier["report_markdown"] == "## Relatorio antigo"


def test_execucao_de_outro_usuario_por_uuid_e_404(client, auth_headers, session_factory):
    """Isolamento vale para a forma uuid tanto quanto para o sha."""
    alheio = ScanJob(
        commit_sha="e" * 40, repo_url="https://github.com/acme/repo",
        installation_id=1, tier1_status=TierStatus.DONE, user_id=uuid4(),
    )
    with session_factory() as s:
        SQLAlchemyScanJobRepository(s).save(alheio)
        s.commit()

    assert client.get(f"/scans/{alheio.id}", headers=auth_headers).status_code == 404
    assert client.get(
        f"/scans/{alheio.id}/history", headers=auth_headers
    ).status_code == 404
