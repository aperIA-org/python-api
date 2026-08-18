"""Testes do writer best-effort de ScanReport.

Religa ``SCAN_PERSISTENCE_ENABLED`` (o autouse desliga por padrão) e aponta
o ``SessionLocal`` do writer para um sqlite in-memory.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.persistence import scan_report_writer
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
from app.infrastructure.persistence.models.scan_report_model import ScanReportModel
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)


@pytest.fixture
def sqlite_factory():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    try:
        yield factory
    finally:
        eng.dispose()


@pytest.fixture
def persistence_on(sqlite_factory):
    original = settings.SCAN_PERSISTENCE_ENABLED
    settings.SCAN_PERSISTENCE_ENABLED = True
    with patch.object(scan_report_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def _cria_execucao(factory, **overrides) -> ScanJob:
    """Insere a execução dona do relatório e devolve a entidade.

    ``scan_job_id`` é NOT NULL: sem execução não há onde pendurar o relatório.
    """
    base = {
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/r",
        "installation_id": 1,
        "tier1_status": TierStatus.DONE,
        "tier1_started_at": datetime(2026, 8, 1, 10, 0),
    }
    base.update(overrides)
    job = ScanJob(**base)
    with factory() as s:
        SQLAlchemyScanJobRepository(s).save(job)
        s.commit()
    return job


def test_persist_report(persistence_on):
    job = _cria_execucao(persistence_on)

    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=2, report_markdown="## r",
        analysis_json={"risk_score": {"score": 60, "level": "medium"}},
        degraded=False, comment_id=42, posted=True,
    )
    with persistence_on() as s:
        r = SQLAlchemyScanReportRepository(s).get_by_scan_job_and_tier(job.id, 2)
    assert r is not None
    assert r.comment_id == 42
    assert r.report_markdown == "## r"
    assert r.scan_job_id == job.id


def test_persist_report_grava_na_execucao_corrente_sem_tocar_na_anterior(persistence_on):
    """O canvas só carrega o ``commit_sha``; o writer resolve para a execução
    corrente. O relatório da execução anterior tem que sobreviver a isso — é a
    razão de o histórico existir.
    """
    primeira = _cria_execucao(persistence_on, tier1_started_at=datetime(2026, 8, 1, 10, 0))
    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=2, report_markdown="## execucao 1",
        analysis_json={}, degraded=False, comment_id=1, posted=True,
    )

    segunda = _cria_execucao(persistence_on, tier1_started_at=datetime(2026, 8, 1, 12, 0))
    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=2, report_markdown="## execucao 2",
        analysis_json={}, degraded=True, comment_id=2, posted=False,
    )

    with persistence_on() as s:
        repo = SQLAlchemyScanReportRepository(s)
        antigo = repo.get_by_scan_job_and_tier(primeira.id, 2)
        novo = repo.get_by_scan_job_and_tier(segunda.id, 2)
    assert antigo.report_markdown == "## execucao 1"
    assert antigo.comment_id == 1 and antigo.degraded is False
    assert novo.report_markdown == "## execucao 2"
    assert novo.degraded is True


def test_persist_report_sem_execucao_nao_grava(persistence_on):
    """Sem ScanJob não há a quem pertencer: o writer loga e desiste.

    Antes a linha era gravada com ``scan_job_id=None`` — um relatório órfão,
    hoje impossível (NOT NULL) e inalcançável por qualquer rota.
    """
    scan_report_writer.persist_report(
        commit_sha="a" * 40, tier=2, report_markdown="## r",
        analysis_json={}, degraded=False, comment_id=None, posted=False,
    )
    with persistence_on() as s:
        assert s.query(ScanReportModel).count() == 0


def test_disabled_is_noop(sqlite_factory):
    # A execução existe: se o flag fosse ignorado, o relatório seria gravado.
    job = _cria_execucao(sqlite_factory)
    with patch.object(scan_report_writer, "SessionLocal", sqlite_factory):
        scan_report_writer.persist_report(
            commit_sha="a" * 40, tier=2, report_markdown="x",
            analysis_json={}, degraded=False, comment_id=None, posted=False,
        )
    with sqlite_factory() as s:
        assert SQLAlchemyScanReportRepository(s).get_by_scan_job_and_tier(job.id, 2) is None
