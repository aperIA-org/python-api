"""Testes do writer best-effort de ScanJob.

O autouse ``disable_scan_persistence`` (conftest) desliga a escrita por
padrão — aqui religamos via ``persistence_on`` e apontamos o ``SessionLocal``
do writer para um sqlite in-memory.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.infrastructure.persistence import scan_job_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
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
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def _read(factory, commit_sha="a" * 40):
    with factory() as s:
        return SQLAlchemyScanJobRepository(s).get_by_commit(commit_sha)


def test_create_scan_job(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        pr_number=3, repo_full_name="acme/repo",
    )
    job = _read(persistence_on)
    assert job is not None
    assert job.tier1_status == TierStatus.RUNNING
    assert job.tier1_started_at is not None


def test_redisparo_empilha_nova_execucao(persistence_on):
    """Rescanear o mesmo commit insere uma linha nova, sem apagar a anterior.

    Antes havia UNIQUE em ``commit_sha`` e o redisparo reaproveitava a linha
    (``restart_execution``), então o resultado da execução anterior sumia.
    """
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier("a" * 40, 1, "done")
    scan_job_writer.mark_tier("a" * 40, 2, "done")
    scan_job_writer.mark_blocked("a" * 40, 2)
    scan_job_writer.set_final_risk_from_analysis(
        "a" * 40, {"risk_score": {"score": 70, "level": "high"}}
    )
    primeira = _read(persistence_on)
    assert primeira.em_andamento() is False  # encerrada: o índice parcial libera

    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )

    with persistence_on() as s:
        repo = SQLAlchemyScanJobRepository(s)
        assert repo.count() == 2
        execucoes = repo.list_by_commit("a" * 40)
        anterior = repo.get_by_id(primeira.id)

    segunda = _read(persistence_on)
    assert segunda.id != primeira.id
    assert [j.id for j in execucoes] == [segunda.id, primeira.id]

    # a nova nasce em branco...
    assert segunda.tier1_status == TierStatus.RUNNING
    assert segunda.tier1_started_at >= primeira.tier1_started_at
    assert segunda.tier1_completed_at is None
    assert segunda.tier2_status is None
    assert segunda.blocked_at_tier is None
    assert segunda.final_risk_score is None and segunda.final_risk_level is None
    # created_at agora é o início DESTA execução, não a entrada do commit.
    assert segunda.created_at == segunda.tier1_started_at
    assert segunda.created_at > primeira.created_at

    # ...e a anterior continua exatamente como estava
    assert anterior.tier1_status == TierStatus.DONE
    assert anterior.tier1_completed_at == primeira.tier1_completed_at
    assert anterior.tier2_status == TierStatus.DONE
    assert anterior.blocked_at_tier == primeira.blocked_at_tier
    assert anterior.final_risk_score == 70 and anterior.final_risk_level == "high"


def test_redisparo_com_execucao_em_andamento_nao_duplica(persistence_on):
    """A idempotência do disparo sobreviveu à queda do UNIQUE.

    Dois webhooks do mesmo push não podem virar dois pipelines: o segundo colide
    com a execução que o primeiro deixou em andamento (índice unique parcial) e
    o ON CONFLICT DO NOTHING o descarta.
    """
    for _ in range(2):
        scan_job_writer.create_scan_job(
            commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        )

    job = _read(persistence_on)
    assert job.em_andamento() is True
    with persistence_on() as s:
        assert SQLAlchemyScanJobRepository(s).count() == 1


def test_mark_tier(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier("a" * 40, 2, "done")
    job = _read(persistence_on)
    assert job.tier2_status == TierStatus.DONE
    assert job.tier2_completed_at is not None


def test_mark_tier_skipped(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier_skipped("a" * 40, 3)
    job = _read(persistence_on)
    assert job.tier3_status == TierStatus.SKIPPED
    assert job.tier3_completed_at is not None


@pytest.mark.parametrize("status_final", ["done", "failed"])
def test_mark_tier_skipped_nao_sobrescreve_desfecho_real(persistence_on, status_final):
    """Pular é decisão sobre um tier que não rodou — se ele rodou, não mexe."""
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier("a" * 40, 3, status_final)
    scan_job_writer.mark_tier_skipped("a" * 40, 3)
    assert _read(persistence_on).tier3_status == TierStatus(status_final)


def test_mark_tier_skipped_sem_commit_sha_e_noop(persistence_on):
    # Guarda contra o bug original: commit_sha vazio não pode virar UPDATE
    # sem WHERE útil nem log de erro.
    scan_job_writer.mark_tier_skipped("", 3)
    assert _read(persistence_on) is None


def test_mark_blocked(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_blocked("a" * 40, 1)
    assert _read(persistence_on).blocked_at_tier.value == 1


def test_set_final_risk_from_analysis_tier2(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.set_final_risk_from_analysis(
        "a" * 40, {"risk_score": {"score": 70, "level": "high"}}
    )
    job = _read(persistence_on)
    assert job.final_risk_score == 70
    assert job.final_risk_level == "high"


def test_set_final_risk_from_analysis_tier3_adjusted(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.set_final_risk_from_analysis(
        "a" * 40, {"risk_score_adjusted": {"score": 95, "level": "critical"}}
    )
    assert _read(persistence_on).final_risk_score == 95


def test_disabled_is_noop(sqlite_factory):
    # Flag desligada (default do autouse) → não grava nada, mesmo com SessionLocal apontado.
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        scan_job_writer.create_scan_job(
            commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
        )
    assert _read(sqlite_factory) is None


def test_fail_pending_tiers_libera_o_commit(persistence_on):
    """Falha de checkout encerra os tiers pendentes na hora.

    Mesmo efeito da varredura de jobs travados, sem esperar o limiar de
    ``SCAN_STALE_AFTER_MINUTES``: o job deixa de estar ``em_andamento`` e o
    disparo manual daquele commit para de responder 409.
    """
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.fail_pending_tiers("a" * 40, motivo="checkout_tier1: fetch falhou")

    job = _read(persistence_on)
    assert job.tier1_status == TierStatus.FAILED
    assert job.em_andamento() is False


def test_fail_pending_tiers_preserva_tier_concluido(persistence_on):
    scan_job_writer.create_scan_job(
        commit_sha="a" * 40, repo_url="https://github.com/acme/repo", installation_id=1,
    )
    scan_job_writer.mark_tier("a" * 40, 1, "done")
    scan_job_writer.mark_tier("a" * 40, 2, "running")
    scan_job_writer.fail_pending_tiers("a" * 40)

    job = _read(persistence_on)
    assert job.tier1_status == TierStatus.DONE
    assert job.tier2_status == TierStatus.FAILED


def test_fail_pending_tiers_desligado_e_noop(sqlite_factory):
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        scan_job_writer.fail_pending_tiers("a" * 40)
    assert _read(sqlite_factory) is None
