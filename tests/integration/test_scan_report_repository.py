"""Testes do repositório síncrono de ScanReport (sqlite in-memory).

Um relatório pertence a uma EXECUÇÃO (``scan_job_id``), não ao commit: a chave
do upsert é ``(scan_job_id, tier)``. Por isso os testes daqui sempre inserem o
``ScanJob`` dono antes — ``scan_job_id`` é NOT NULL.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.scan.entities import ScanJob
from app.domain.scan.report_entities import ScanReport
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    scan_report_model,
    scan_tool_run_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)


SHA = "a" * 40


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
def session(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with factory() as s:
        yield s


def _execucao(session, commit_sha: str = SHA, **overrides) -> ScanJob:
    """Insere uma execução e devolve a entidade (dona dos relatórios).

    O default deixa a execução ENCERRADA (``tier1_status=done``) porque o índice
    unique parcial só admite uma execução em andamento por commit — empilhar
    duas execuções do mesmo commit exige que a anterior já tenha desfecho.
    """
    base = {
        "commit_sha": commit_sha,
        "repo_url": "https://github.com/acme/repo",
        "installation_id": 1,
        "tier1_status": TierStatus.DONE,
        "tier1_started_at": datetime(2026, 8, 1, 10, 0),
    }
    base.update(overrides)
    job = ScanJob(**base)
    SQLAlchemyScanJobRepository(session).save(job)
    session.commit()
    return job


def _report(job: ScanJob, tier: int = 2, **overrides) -> ScanReport:
    base = {
        "commit_sha": job.commit_sha,
        "scan_job_id": job.id,
        "tier": tier,
        "report_markdown": f"## relatorio tier {tier}",
        "analysis_json": {"risk_score": {"score": 70, "level": "high"}},
        "degraded": False,
        "comment_id": 555,
        "posted": True,
    }
    base.update(overrides)
    return ScanReport(**base)


def test_save_and_get_by_scan_job_and_tier(session):
    repo = SQLAlchemyScanReportRepository(session)
    job = _execucao(session)
    repo.save(_report(job, 2))
    session.commit()

    r = repo.get_by_scan_job_and_tier(job.id, 2)
    assert r is not None
    assert r.report_markdown == "## relatorio tier 2"
    assert r.analysis_json["risk_score"]["score"] == 70
    assert r.posted is True


def test_get_by_scan_job_orders_by_tier(session):
    repo = SQLAlchemyScanReportRepository(session)
    job = _execucao(session)
    repo.save(_report(job, 3, report_markdown="t3"))
    repo.save(_report(job, 2, report_markdown="t2"))
    session.commit()

    reports = repo.get_by_scan_job(job.id)
    assert [r.tier for r in reports] == [2, 3]


def test_save_upserts_dentro_da_mesma_execucao(session):
    """Replay do canvas (acks_late) reescreve o relatório daquele tier.

    O conflito é por ``(scan_job_id, tier)``: a mesma execução só pode ter um
    relatório por tier, e a segunda escrita substitui a primeira.
    """
    repo = SQLAlchemyScanReportRepository(session)
    job = _execucao(session)
    repo.save(_report(job, 2, report_markdown="antigo", posted=False))
    session.commit()
    repo.save(_report(job, 2, report_markdown="novo", posted=True, comment_id=999))
    session.commit()

    reports = repo.get_by_scan_job(job.id)
    assert len(reports) == 1
    assert reports[0].report_markdown == "novo"
    assert reports[0].posted is True
    assert reports[0].comment_id == 999


def test_execucoes_do_mesmo_commit_guardam_relatorios_separados(session):
    """O coração do histórico: rescanear não apaga o relatório anterior.

    Enquanto a chave era ``(commit_sha, tier)``, a segunda execução fazia upsert
    em cima da primeira e o markdown antigo desaparecia.
    """
    repo = SQLAlchemyScanReportRepository(session)
    primeira = _execucao(session, tier1_started_at=datetime(2026, 8, 1, 10, 0))
    repo.save(_report(primeira, 2, report_markdown="## execucao 1"))
    session.commit()

    segunda = _execucao(session, tier1_started_at=datetime(2026, 8, 1, 12, 0))
    repo.save(_report(segunda, 2, report_markdown="## execucao 2"))
    session.commit()

    assert primeira.id != segunda.id
    assert repo.get_by_scan_job_and_tier(primeira.id, 2).report_markdown == "## execucao 1"
    assert repo.get_by_scan_job_and_tier(segunda.id, 2).report_markdown == "## execucao 2"
    # duas linhas para o mesmo (commit, tier) — impossível no modelo anterior
    assert len(repo.get_by_scan_job(primeira.id)) == 1
    assert len(repo.get_by_scan_job(segunda.id)) == 1


def test_get_by_scan_job_and_tier_missing(session):
    repo = SQLAlchemyScanReportRepository(session)
    job = _execucao(session)
    repo.save(_report(job, 2))
    session.commit()

    # execução existe, tier não
    assert repo.get_by_scan_job_and_tier(job.id, 3) is None
    # execução inexistente
    assert repo.get_by_scan_job_and_tier(_execucao(session, "z" * 40).id, 2) is None
