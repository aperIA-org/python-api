"""Testes do repositório síncrono de ScanJob (sqlite in-memory)."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus
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


def _make_job(commit_sha: str = "a" * 40, **overrides) -> ScanJob:
    base = {
        "commit_sha": commit_sha,
        "repo_url": "https://github.com/acme/repo",
        "installation_id": 123,
        "pr_number": 7,
        "repo_full_name": "acme/repo",
        "tier1_status": TierStatus.RUNNING,
    }
    base.update(overrides)
    return ScanJob(**base)


def test_save_and_get_by_commit(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()

    job = repo.get_by_commit("a" * 40)
    assert job is not None
    assert job.repo_full_name == "acme/repo"
    assert job.tier1_status == TierStatus.RUNNING


def test_save_is_idempotent_on_commit(session):
    """Dois disparos simultâneos do mesmo commit não geram dois pipelines.

    Quem garante isso agora é o índice unique PARCIAL
    (``uq_scan_jobs_commit_em_andamento``), não mais um UNIQUE em ``commit_sha``:
    o primeiro job fica ``tier1_status=running``, então o segundo cai no
    predicado "em andamento" e o ON CONFLICT DO NOTHING o descarta. A linha que
    sobrevive é a PRIMEIRA — DO NOTHING, não sobrescrita.
    """
    repo = SQLAlchemyScanJobRepository(session)
    primeiro = _make_job(tier1_status=TierStatus.RUNNING)
    repo.save(primeiro)
    session.commit()
    repo.save(_make_job(tier1_status=TierStatus.RUNNING))
    session.commit()

    assert repo.count() == 1
    assert repo.get_by_commit("a" * 40).id == primeiro.id


def test_save_permite_nova_execucao_quando_a_anterior_encerrou(session):
    """O índice parcial só cobre execuções vivas — encerradas não conflitam.

    É exatamente essa brecha que dá origem ao histórico: rescanear o mesmo
    commit empilha uma linha em vez de reescrever a anterior.
    """
    repo = SQLAlchemyScanJobRepository(session)
    encerrada = _make_job(
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 8, 1, 10, 0),
        tier2_status=TierStatus.DONE,
    )
    repo.save(encerrada)
    session.commit()

    nova = _make_job(
        tier1_status=TierStatus.RUNNING, tier1_started_at=datetime(2026, 8, 1, 12, 0)
    )
    repo.save(nova)
    session.commit()

    assert repo.count() == 2
    assert repo.get_by_commit("a" * 40).id == nova.id  # a corrente é a mais recente


def test_update_tier_status_sets_timestamps(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()

    repo.update_tier_status("a" * 40, ScanTier.TWO, TierStatus.RUNNING)
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.tier2_status == TierStatus.RUNNING
    assert job.tier2_started_at is not None
    assert job.tier2_completed_at is None

    repo.update_tier_status("a" * 40, ScanTier.TWO, TierStatus.DONE)
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.tier2_status == TierStatus.DONE
    assert job.tier2_completed_at is not None


def test_set_blocked(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()
    repo.set_blocked("a" * 40, ScanTier.ONE)
    session.commit()
    assert repo.get_by_commit("a" * 40).blocked_at_tier == ScanTier.ONE


def test_set_final_risk(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job())
    session.commit()
    repo.set_final_risk("a" * 40, 82, "high")
    session.commit()
    job = repo.get_by_commit("a" * 40)
    assert job.final_risk_score == 82
    assert job.final_risk_level == "high"


def test_list_in_progress_ignora_jobs_concluidos(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job("a" * 40, tier1_status=TierStatus.RUNNING))
    repo.save(_make_job("b" * 40, tier1_status=TierStatus.DONE, tier2_status=TierStatus.QUEUED))
    repo.save(
        _make_job(
            "c" * 40,
            tier1_status=TierStatus.DONE,
            tier2_status=TierStatus.DONE,
            tier3_status=TierStatus.SKIPPED,
        )
    )
    session.commit()

    em_andamento = {j.commit_sha for j in repo.list_in_progress()}
    assert em_andamento == {"a" * 40, "b" * 40}


def test_fail_pending_tiers_preserva_tiers_concluidos(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(
        _make_job(
            "a" * 40,
            tier1_status=TierStatus.DONE,
            tier1_completed_at=datetime(2026, 7, 31, 5, 30),
            tier2_status=TierStatus.RUNNING,
        )
    )
    session.commit()

    repo.fail_pending_tiers("a" * 40)
    session.commit()

    job = repo.get_by_commit("a" * 40)
    assert job.tier1_status == TierStatus.DONE  # concluído não é reescrito
    assert job.tier1_completed_at == datetime(2026, 7, 31, 5, 30)
    assert job.tier2_status == TierStatus.FAILED
    assert job.tier2_completed_at is not None
    assert job.tier3_status is None  # tier que nunca rodou continua vazio


def _execucao_encerrada() -> ScanJob:
    """Uma execução com desfecho completo, usada como "a execução anterior"."""
    return _make_job(
        "a" * 40,
        created_at=datetime(2026, 7, 31, 5, 30),
        tier1_status=TierStatus.DONE,
        tier1_started_at=datetime(2026, 7, 31, 5, 30),
        tier1_completed_at=datetime(2026, 8, 1, 3, 39),
        tier2_status=TierStatus.FAILED,
        tier2_started_at=datetime(2026, 8, 1, 3, 39),
        tier3_status=TierStatus.SKIPPED,
        blocked_at_tier=ScanTier.TWO,
        final_risk_score=80,
        final_risk_level="high",
    )


def test_redisparo_empilha_execucao_preservando_a_anterior(session):
    """Rescanear o mesmo commit cria uma linha NOVA e não toca na antiga.

    Substitui o antigo ``restart_execution``, que zerava a linha existente
    porque havia UNIQUE em ``commit_sha`` — o resultado anterior era destruído.
    """
    repo = SQLAlchemyScanJobRepository(session)
    anterior = _execucao_encerrada()
    repo.save(anterior)
    session.commit()

    novo_inicio = datetime(2026, 8, 1, 10, 0)
    nova = _make_job(
        "a" * 40,
        created_at=novo_inicio,
        tier1_status=TierStatus.RUNNING,
        tier1_started_at=novo_inicio,
    )
    repo.save(nova)
    session.commit()

    assert repo.count() == 2

    # a execução corrente é a nova, em branco
    corrente = repo.get_by_commit("a" * 40)
    assert corrente.id == nova.id
    assert corrente.tier1_status == TierStatus.RUNNING
    assert corrente.tier1_started_at == novo_inicio
    assert corrente.tier1_completed_at is None
    assert corrente.tier2_status is None and corrente.tier3_status is None
    assert corrente.blocked_at_tier is None
    assert corrente.final_risk_score is None and corrente.final_risk_level is None
    # created_at agora é o início DESTA execução (não há mais o que preservar)
    assert corrente.created_at == novo_inicio

    # a anterior sobrevive intacta: statuses, timestamps e risco
    velha = repo.get_by_id(anterior.id)
    assert velha.tier1_status == TierStatus.DONE
    assert velha.tier1_started_at == datetime(2026, 7, 31, 5, 30)
    assert velha.tier1_completed_at == datetime(2026, 8, 1, 3, 39)
    assert velha.tier2_status == TierStatus.FAILED
    assert velha.tier2_started_at == datetime(2026, 8, 1, 3, 39)
    assert velha.tier3_status == TierStatus.SKIPPED
    assert velha.blocked_at_tier == ScanTier.TWO
    assert velha.final_risk_score == 80 and velha.final_risk_level == "high"
    assert velha.created_at == datetime(2026, 7, 31, 5, 30)

    # e o histórico vem da mais recente para a mais antiga
    assert [j.id for j in repo.list_by_commit("a" * 40)] == [nova.id, anterior.id]


def test_writes_atingem_apenas_a_execucao_corrente(session):
    """As tasks Celery só conhecem o ``commit_sha``.

    Com histórico, um ``WHERE commit_sha = X`` reescreveria TODAS as execuções
    de uma vez; os writes resolvem para a execução corrente antes de atualizar.
    """
    repo = SQLAlchemyScanJobRepository(session)
    anterior = _execucao_encerrada()
    repo.save(anterior)
    session.commit()

    nova = _make_job(
        "a" * 40,
        created_at=datetime(2026, 8, 1, 10, 0),
        tier1_status=TierStatus.RUNNING,
        tier1_started_at=datetime(2026, 8, 1, 10, 0),
    )
    repo.save(nova)
    session.commit()

    repo.update_tier_status("a" * 40, ScanTier.TWO, TierStatus.DONE)
    repo.set_blocked("a" * 40, ScanTier.THREE)
    repo.set_final_risk("a" * 40, 20, "low")
    session.commit()

    corrente = repo.get_by_id(nova.id)
    assert corrente.tier2_status == TierStatus.DONE
    assert corrente.blocked_at_tier == ScanTier.THREE
    assert corrente.final_risk_score == 20

    velha = repo.get_by_id(anterior.id)
    assert velha.tier2_status == TierStatus.FAILED
    assert velha.blocked_at_tier == ScanTier.TWO
    assert velha.final_risk_score == 80


def test_list_recent_and_count(session):
    repo = SQLAlchemyScanJobRepository(session)
    repo.save(_make_job("a" * 40))
    repo.save(_make_job("b" * 40))
    session.commit()
    assert repo.count() == 2
    items = repo.list_recent(limit=1, offset=0)
    assert len(items) == 1
