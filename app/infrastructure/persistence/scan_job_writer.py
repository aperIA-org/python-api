"""Persistência best-effort do ciclo de vida do ``ScanJob``.

Mesmo racional do ``finding_writer``: os workers Celery são síncronos e
abrem a própria ``Session`` via ``SessionLocal``. A escrita é
**best-effort** — qualquer falha de banco é logada mas NUNCA interrompe o
pipeline. O canvas Celery opera sobre os dicts que trafegam entre as
tasks, não sobre o banco; o ``scan_jobs`` é apenas a projeção consumível
via API (``GET /scans``).

Tudo é chaveado por ``commit_sha`` — a única identidade que flui no canvas
Celery. Como agora existem várias execuções por commit, o repositório resolve
isso para a **execução corrente** (ver ``_id_execucao_corrente``); estas funções
continuam falando em ``commit_sha`` de propósito, para não ter que costurar um
id novo por todas as assinaturas de task.

Gated por ``settings.SCAN_PERSISTENCE_ENABLED`` (testes desligam).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog

from app.config import settings
from app.domain.scan.entities import ScanJob
from app.domain.scan.value_objects import ScanTier, TierStatus
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)

logger = structlog.get_logger()


def create_scan_job(
    *,
    commit_sha: str,
    repo_url: str,
    installation_id: int,
    pr_number: int | None = None,
    repo_full_name: str | None = None,
    user_id: UUID | None = None,
    repository_id: UUID | None = None,
) -> None:
    """Insere uma **execução nova** no início do pipeline, com o Tier 1 já em
    ``running``.

    Redisparar o mesmo commit (novo push com o mesmo HEAD, scan manual repetido,
    retry) empilha uma linha em vez de reescrever a anterior — é assim que o
    histórico de relatórios existe. Antes havia UNIQUE em ``commit_sha`` e a
    execução anterior era sobrescrita por ``restart_execution``.

    A idempotência continua garantida pelo índice unique parcial
    (``uq_scan_jobs_commit_em_andamento``): dois disparos simultâneos do mesmo
    commit não geram dois pipelines, porque o segundo colide com a execução que
    o primeiro deixou em andamento e o ON CONFLICT DO NOTHING o descarta.

    ``created_at`` agora é o início desta execução — não há mais o que preservar
    de uma linha anterior.

    ``user_id``/``repository_id`` atribuem o scan ao dono (multi-tenant); ficam
    ``None`` para webhooks de repositórios não cadastrados (scan órfão, que não
    aparece na leitura isolada de nenhum usuário).
    """
    if not settings.SCAN_PERSISTENCE_ENABLED:
        return
    try:
        iniciado_em = datetime.utcnow()
        job = ScanJob(
            commit_sha=commit_sha,
            repo_url=repo_url,
            installation_id=installation_id,
            pr_number=pr_number,
            repo_full_name=repo_full_name,
            tier1_status=TierStatus.RUNNING,
            tier1_started_at=iniciado_em,
            created_at=iniciado_em,
            user_id=user_id,
            repository_id=repository_id,
        )
        with SessionLocal() as db:
            # ON CONFLICT DO NOTHING contra o índice parcial: cobre a corrida
            # entre dois disparos simultâneos do mesmo commit.
            SQLAlchemyScanJobRepository(db).save(job)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort: nunca quebra o pipeline
        logger.warning("scan_job_create_failed", commit_sha=commit_sha, error=str(exc))
        return
    logger.info("scan_job_created", commit_sha=commit_sha, scan_job_id=str(job.id))


def mark_tier(commit_sha: str, tier: int, status: str) -> None:
    """Atualiza o status de um tier (best-effort). ``tier`` 1..3, ``status``
    é o valor de ``TierStatus`` (ex.: "running", "done", "skipped").
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).update_tier_status(
                commit_sha, ScanTier(tier), TierStatus(status)
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_tier_update_failed",
            commit_sha=commit_sha,
            tier=tier,
            status=status,
            error=str(exc),
        )


def mark_tier_skipped(commit_sha: str, tier: int) -> None:
    """Registra que um gate DECIDIU não rodar um tier (best-effort).

    Diferente de ``mark_tier(..., "skipped")`` em um ponto: nunca sobrescreve
    um tier que já tem desfecho real (``done``/``failed``). Sem essa checagem,
    um gate que rodasse fora de ordem (retry do canvas, redisparo) apagaria na
    projeção o resultado de um tier que de fato executou.

    ``tier3_status = NULL`` no dashboard vira um traço apagado, igual a "ainda
    não chegou nesse tier" — mas pular é uma decisão tomada, e ela precisa
    aparecer.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            repo = SQLAlchemyScanJobRepository(db)
            job = repo.get_by_commit(commit_sha)
            if job is None or job.tier_concluido(ScanTier(tier)):
                return
            repo.update_tier_status(commit_sha, ScanTier(tier), TierStatus.SKIPPED)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_tier_skip_failed",
            commit_sha=commit_sha,
            tier=tier,
            error=str(exc),
        )


def fail_pending_tiers(commit_sha: str, *, motivo: str = "") -> None:
    """Encerra como ``failed`` todo tier ainda ``queued``/``running``.

    É a **mesma** operação que ``RecoverStaleScanJobsUseCase`` aplica na
    varredura de boot — só que aqui é imediata, disparada por quem já sabe que
    o pipeline não vai continuar (ex.: o checkout do repositório falhou e não
    há árvore para escanear). Idempotente e conservadora (o CASE do
    repositório preserva os tiers já concluídos), então as duas rotas não
    conflitam: se esta rodar primeiro, o job deixa de estar ``em_andamento`` e
    a varredura nem o enxerga.

    Sem isso o commit ficaria preso em ``running`` até o limiar de
    ``SCAN_STALE_AFTER_MINUTES`` — e o disparo manual responderia 409 nesse
    intervalo inteiro.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).fail_pending_tiers(commit_sha)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_fail_pending_failed", commit_sha=commit_sha, error=str(exc)
        )
        return
    logger.warning("scan_job_tiers_falhados", commit_sha=commit_sha, motivo=motivo)


def mark_blocked(commit_sha: str, tier: int) -> None:
    """Registra em qual tier o pipeline foi bloqueado (best-effort)."""
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).set_blocked(commit_sha, ScanTier(tier))
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_block_update_failed", commit_sha=commit_sha, tier=tier, error=str(exc)
        )


def set_final_risk_from_analysis(commit_sha: str, analysis: dict[str, Any] | None) -> None:
    """Extrai o risco da análise do Claude e persiste no ``ScanJob``.

    Aceita tanto o formato do Tier 2 (``risk_score``) quanto o do Tier 3
    (``risk_score_adjusted``), ambos no shape ``{"score": int, "level": str}``.
    Best-effort: se o dado não existe, apenas não escreve.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha or not analysis:
        return
    risk = analysis.get("risk_score_adjusted") or analysis.get("risk_score")
    if not isinstance(risk, dict):
        return
    score = risk.get("score")
    level = risk.get("level")
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).set_final_risk(commit_sha, score, level)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_final_risk_update_failed", commit_sha=commit_sha, error=str(exc)
        )


def set_celery_task_id(commit_sha: str, task_id: str) -> None:
    """Guarda a raiz do canvas logo após o dispatch. Best-effort.

    Falhar aqui não pode derrubar um pipeline que já está andando — só custa a
    possibilidade de cancelar aquela execução, e a rota diz isso com 409.
    """
    if not settings.SCAN_PERSISTENCE_ENABLED or not commit_sha or not task_id:
        return
    try:
        with SessionLocal() as db:
            SQLAlchemyScanJobRepository(db).set_celery_task_id(commit_sha, task_id)
            db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        logger.warning(
            "scan_job_task_id_nao_gravado", commit_sha=commit_sha, error=str(exc)
        )
