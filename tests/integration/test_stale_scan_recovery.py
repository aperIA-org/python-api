"""Recuperação de ScanJobs travados (órfãos do broker).

Cenário reproduzido: a API grava a linha do ``ScanJob`` no Postgres e publica
as tarefas do tier 1 no Redis; a stack é recriada antes de um worker consumir a
fila. A tarefa evapora, a linha sobrevive dizendo ``running`` para sempre — e
bloqueia novos scans daquele commit.

Cobre os dois caminhos de recuperação: a varredura de boot da API
(``app.main.recover_stale_scan_jobs``) e o caso de uso por trás dela.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.application.use_cases.recover_stale_scans_use_case import (
    RecoverStaleScanJobsUseCase,
)
from app.config import settings
from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.main import recover_stale_scan_jobs


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
    try:
        yield factory
    finally:
        eng.dispose()


def _save(factory, commit_sha, **overrides):
    base = {
        "commit_sha": commit_sha,
        "repo_url": "https://github.com/acme/api",
        "installation_id": 42,
        "repo_full_name": "acme/api",
    }
    base.update(overrides)
    with factory() as s:
        SQLAlchemyScanJobRepository(s).save(ScanJob(**base))
        s.commit()


def _read(factory, commit_sha):
    with factory() as s:
        return SQLAlchemyScanJobRepository(s).get_by_commit(commit_sha)


def test_varredura_libera_job_preso_no_tier1(session_factory):
    # Linha órfã: nasceu com tier1 "running" e nunca mais progrediu.
    _save(
        session_factory,
        "a" * 40,
        tier1_status=TierStatus.RUNNING,
        created_at=datetime.utcnow() - timedelta(hours=22),
    )

    with session_factory() as s:
        liberados = RecoverStaleScanJobsUseCase(
            SQLAlchemyScanJobRepository(s), stale_after_minutes=30
        ).execute()
        s.commit()

    assert liberados == ["a" * 40]
    job = _read(session_factory, "a" * 40)
    assert job.tier1_status == TierStatus.FAILED
    assert job.tier1_completed_at is not None
    assert job.em_andamento() is False


def test_varredura_nao_toca_em_job_recente(session_factory):
    _save(
        session_factory,
        "b" * 40,
        tier1_status=TierStatus.RUNNING,
        created_at=datetime.utcnow() - timedelta(minutes=2),
    )

    with session_factory() as s:
        liberados = RecoverStaleScanJobsUseCase(
            SQLAlchemyScanJobRepository(s), stale_after_minutes=30
        ).execute()
        s.commit()

    assert liberados == []
    assert _read(session_factory, "b" * 40).tier1_status == TierStatus.RUNNING


def test_varredura_preserva_tiers_ja_concluidos(session_factory):
    _save(
        session_factory,
        "c" * 40,
        tier1_status=TierStatus.DONE,
        tier1_completed_at=datetime.utcnow() - timedelta(hours=5),
        tier2_status=TierStatus.RUNNING,
        tier2_started_at=datetime.utcnow() - timedelta(hours=5),
        created_at=datetime.utcnow() - timedelta(hours=6),
    )

    with session_factory() as s:
        RecoverStaleScanJobsUseCase(
            SQLAlchemyScanJobRepository(s), stale_after_minutes=30
        ).execute()
        s.commit()

    job = _read(session_factory, "c" * 40)
    assert job.tier1_status == TierStatus.DONE
    assert job.tier2_status == TierStatus.FAILED


def test_startup_da_api_roda_a_varredura(session_factory, monkeypatch):
    """O handler de startup real (``app.main``) libera o job preso."""
    monkeypatch.setattr(settings, "SCAN_PERSISTENCE_ENABLED", True)
    monkeypatch.setattr(settings, "SCAN_STALE_AFTER_MINUTES", 30)
    _save(
        session_factory,
        "d" * 40,
        tier1_status=TierStatus.RUNNING,
        created_at=datetime.utcnow() - timedelta(hours=3),
    )

    with patch("app.main.SessionLocal", session_factory):
        recover_stale_scan_jobs()

    assert _read(session_factory, "d" * 40).tier1_status == TierStatus.FAILED


def test_startup_e_noop_com_persistencia_desligada(session_factory):
    # Flag desligada é o default do autouse ``disable_scan_persistence``.
    _save(
        session_factory,
        "e" * 40,
        tier1_status=TierStatus.RUNNING,
        created_at=datetime.utcnow() - timedelta(hours=3),
    )

    with patch("app.main.SessionLocal", session_factory):
        recover_stale_scan_jobs()

    assert _read(session_factory, "e" * 40).tier1_status == TierStatus.RUNNING


def test_startup_nao_derruba_a_api_quando_o_banco_falha(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_PERSISTENCE_ENABLED", True)

    def _boom():
        raise RuntimeError("banco indisponivel")

    with patch("app.main.SessionLocal", _boom):
        recover_stale_scan_jobs()  # best-effort: não levanta
